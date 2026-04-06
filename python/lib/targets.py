"""
Target management for ConfigManBearPig.

Translated from PowerShell Add-DeviceToTargets, Add-DeviceToTargetsA,
Test-AllowedTarget, and related target management functions.
"""

import logging
import socket
import threading
from typing import Any, Optional

from lib.ad_resolver import ADResolver

logger = logging.getLogger("ConfigManBearPig")


class CollectionTarget:
    """
    Represents a collection target system.

    Stores hostname (FQDN preferred), AD object info, collection source,
    and per-host phase completion tracking.
    """

    def __init__(
        self,
        hostname: str,
        ad_object: Optional[dict[str, Any]] = None,
        source: str = "Unknown",
    ):
        self.hostname: str = hostname
        self.ad_object: Optional[dict[str, Any]] = ad_object
        self.source: str = source
        self.collected: bool = False
        self.phase_status: dict[str, str] = {}  # phase -> "NotStarted"|"InProgress"|"Complete"|"Failed"

    @property
    def sid(self) -> Optional[str]:
        """Get the SID from the AD object if available."""
        if self.ad_object:
            return self.ad_object.get("SID") or self.ad_object.get("objectSid")
        return None

    @property
    def fqdn(self) -> Optional[str]:
        """Get FQDN from AD object or hostname."""
        if self.ad_object and self.ad_object.get("dNSHostName"):
            return self.ad_object["dNSHostName"]
        if "." in self.hostname:
            return self.hostname
        return None

    @property
    def short_name(self) -> str:
        """Get the short hostname."""
        return self.hostname.split(".")[0]


class TargetManager:
    """
    Manages collection targets with deduplication and allow-list filtering.

    Translated from PowerShell $script:CollectionTargets management,
    Add-DeviceToTargets (lines 1317-1416), Add-DeviceToTargetsA (lines 1195-1260),
    and Test-AllowedTarget (lines 1263-1315).
    """

    def __init__(
        self,
        ad_resolver: ADResolver,
        allowed_targets: Optional[set[str]] = None,
    ):
        """
        Args:
            ad_resolver: AD resolver for looking up computer objects
            allowed_targets: Optional set of allowed hostnames (filter)
        """
        self.ad_resolver = ad_resolver
        self.allowed_targets = allowed_targets
        # Keyed by canonical hostname (FQDN preferred, case-insensitive)
        self._targets: dict[str, CollectionTarget] = {}
        # SID -> hostname mapping for dedup
        self._sid_map: dict[str, str] = {}
        # Thread safety lock for concurrent access
        self._lock = threading.RLock()

    @property
    def targets(self) -> dict[str, CollectionTarget]:
        """Return all targets (snapshot for iteration safety)."""
        with self._lock:
            return dict(self._targets)

    @property
    def count(self) -> int:
        """Number of targets."""
        with self._lock:
            return len(self._targets)

    def add_device(
        self,
        device_name: str,
        source: str = "Unknown",
        ad_object: Optional[dict[str, Any]] = None,
    ) -> Optional[CollectionTarget]:
        """
        Add a device to collection targets with deduplication.

        Translated from PowerShell Add-DeviceToTargets (lines 1317-1416).

        Deduplication rules:
        1. If we already have this hostname, merge sources
        2. If we have a matching SID, prefer FQDN over short name
        3. Allow-list filtering applies if configured

        Args:
            device_name: Hostname, FQDN, or IP
            source: How this target was discovered
            ad_object: Pre-resolved AD object (optional)

        Returns:
            CollectionTarget or None if filtered out
        """
        if not device_name:
            return None

        device_name = device_name.strip()
        if not device_name:
            return None

        # Check allow-list filter (no lock needed, allowed_targets is read-only)
        if not self._is_allowed(device_name):
            logger.debug(f"Target {device_name} filtered by allow-list")
            return None

        # Resolve AD object if not provided (outside lock - network I/O)
        if ad_object is None:
            ad_object = self.ad_resolver.get_ad_computer(device_name)
            if ad_object:
                logger.debug(f"Resolved {device_name} to AD object (SID: {ad_object.get('SID', 'unknown')})")
            else:
                logger.debug(f"Could not resolve {device_name} to AD object")

        # Determine canonical hostname (prefer FQDN) - outside lock
        canonical = device_name
        if ad_object and ad_object.get("dNSHostName"):
            canonical = ad_object["dNSHostName"]
        elif "." not in device_name:
            # Try DNS resolution to get FQDN
            try:
                fqdn = socket.getfqdn(device_name)
                if fqdn and "." in fqdn and fqdn != device_name:
                    canonical = fqdn
            except Exception:
                pass

        canonical_lower = canonical.lower()

        # Check SID-based dedup
        sid = None
        if ad_object:
            sid = ad_object.get("SID") or ad_object.get("objectSid")

        with self._lock:
            if sid and sid in self._sid_map:
                existing_key = self._sid_map[sid]
                existing = self._targets.get(existing_key)
                if existing:
                    # Prefer FQDN over short name
                    if "." in canonical and "." not in existing.hostname:
                        logger.debug(
                            f"Upgrading target {existing.hostname} to FQDN {canonical}"
                        )
                        # Move to new key
                        del self._targets[existing_key]
                        existing.hostname = canonical
                        self._targets[canonical_lower] = existing
                        self._sid_map[sid] = canonical_lower
                        existing.source += f",{source}"
                    else:
                        existing.source += f",{source}"
                    return existing

            # Check hostname-based dedup
            if canonical_lower in self._targets:
                existing = self._targets[canonical_lower]
                existing.source += f",{source}"
                if ad_object and not existing.ad_object:
                    existing.ad_object = ad_object
                return existing

            # Also check short name variants
            short_lower = canonical.split(".")[0].lower()
            for key, target in list(self._targets.items()):
                if target.short_name.lower() == short_lower:
                    # Same host, different naming
                    if "." in canonical and "." not in target.hostname:
                        # Upgrade to FQDN
                        del self._targets[key]
                        target.hostname = canonical
                        self._targets[canonical_lower] = target
                        if sid:
                            self._sid_map[sid] = canonical_lower
                        target.source += f",{source}"
                    else:
                        target.source += f",{source}"
                    if ad_object and not target.ad_object:
                        target.ad_object = ad_object
                    return target

            # New target
            target = CollectionTarget(
                hostname=canonical,
                ad_object=ad_object,
                source=source,
            )
            self._targets[canonical_lower] = target
            if sid:
                self._sid_map[sid] = canonical_lower

        logger.info(f"Added collection target: {canonical} (source: {source})")
        return target

    def _is_allowed(self, device_name: str) -> bool:
        """
        Check if a device name is in the allow-list.

        Translated from PowerShell Test-AllowedTarget (lines 1263-1315).
        """
        if self.allowed_targets is None:
            return True  # No filter = allow all

        device_lower = device_name.lower().strip()
        short = device_lower.split(".")[0].rstrip("$")

        for allowed in self.allowed_targets:
            allowed_lower = allowed.lower().strip()
            allowed_short = allowed_lower.split(".")[0].rstrip("$")

            if device_lower == allowed_lower:
                return True
            if short == allowed_short:
                return True
            if device_lower == allowed_lower.rstrip("$"):
                return True

        return False

    def get_target(self, hostname: str) -> Optional[CollectionTarget]:
        """Get a target by hostname."""
        with self._lock:
            hostname_lower = hostname.lower()
            if hostname_lower in self._targets:
                return self._targets[hostname_lower]

            # Try short name match
            short = hostname.split(".")[0].lower()
            for key, target in self._targets.items():
                if target.short_name.lower() == short:
                    return target

            return None

    def mark_collected(self, hostname: str) -> None:
        """Mark a target as successfully collected."""
        target = self.get_target(hostname)
        if target:
            target.collected = True

    def get_uncollected(self) -> list[CollectionTarget]:
        """Get all targets that haven't been collected yet."""
        with self._lock:
            return [t for t in self._targets.values() if not t.collected]
