"""
Shared utilities for CRED-discovered secret handling.

Used by CRED-2 (HTTP), CRED-4 (local/CIM), and CRED-6 (SMB/PXE) collectors
to create proper graph nodes for discovered credentials.

Two tiers of nodes:
- Domain credentials (DOMAIN\\user) → AD-resolved User nodes
- Non-domain credentials (passwords, secrets) → SCCM_Secret nodes
"""

import hashlib
import logging
import re
from typing import Any, Optional

logger = logging.getLogger("ConfigManBearPig")

# Matches DOMAIN\user patterns (e.g., MAYYHEM\svc_naa, CONTOSO\admin)
DOMAIN_USER_PATTERN = re.compile(r"[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+")


def extract_domain_users(text: str) -> list[str]:
    """Extract DOMAIN\\user patterns from text."""
    return DOMAIN_USER_PATTERN.findall(text)


def resolve_and_create_secret_user(
    ad_resolver: Any,  # Optional[ADResolver] — Any to avoid circular import
    graph: Any,  # GraphStore
    username: str,
    secret_type: str,  # "NAA", "CollectionVariable", "TaskSequence"
    site_code: Optional[str],
    collection_source: str,
    extra_props: Optional[dict] = None,
) -> Optional[str]:
    """
    Resolve DOMAIN\\user to AD SID, create User node, return node ID.

    If AD resolution succeeds, the node ID is the AD SID and all AD
    attributes are merged.  If resolution fails, a synthetic ID is used
    but the node is still created as ["User", "Base"] so post-processing
    can find it via discoveredSecretType.
    """
    ad_obj = None
    if ad_resolver is not None:
        try:
            ad_obj = ad_resolver.resolve_principal(username)
        except Exception as e:
            logger.debug(f"AD resolution failed for '{username}': {e}")

    if ad_obj and ad_obj.get("objectSid"):
        node_id = ad_obj["objectSid"]
        sam = ad_obj.get("sAMAccountName", username.split("\\")[-1])
    else:
        # Synthetic ID — still a User node but without AD SID
        node_id = f"SCCM_Secret_{secret_type}_{username}"
        sam = username.split("\\")[-1] if "\\" in username else username
        ad_obj = None

    props: dict[str, Any] = {
        "collectionSource": [collection_source],
        "name": sam,
        "sAMAccountName": sam,
        "discoveredSecretType": secret_type,
        "discoveredInSite": site_code,
    }
    if secret_type == "NAA":
        props["isSCCMNetworkAccessAccount"] = True
    if extra_props:
        props.update(extra_props)

    graph.upsert_node(
        node_id, ["User", "Base"], properties=props, ad_object=ad_obj
    )
    logger.debug(
        f"Created secret User node: {node_id} (type={secret_type}, site={site_code})"
    )
    return node_id


def create_secret_node(
    graph: Any,  # GraphStore
    secret_type: str,  # "NAA_Password", "CollectionVariable", "TaskSequence"
    value: str,
    site_code: Optional[str],
    collection_source: str,
    name: Optional[str] = None,
    show_cleartext: bool = False,
    extra_props: Optional[dict] = None,
) -> str:
    """
    Create an SCCM_Secret node for non-domain credentials.

    Uses a deterministic ID (hash of value) so identical secrets
    discovered from multiple sources are deduplicated.

    Returns node ID.
    """
    val_hash = hashlib.sha256(value.encode()).hexdigest()[:12]
    node_id = f"SCCM_Secret_{secret_type}_{val_hash}"

    props: dict[str, Any] = {
        "collectionSource": [collection_source],
        "secretType": secret_type,
        "discoveredSecretType": secret_type,
        "discoveredInSite": site_code,
        "name": name or secret_type,
    }
    if show_cleartext:
        props["secretValue"] = value
    if extra_props:
        props.update(extra_props)

    graph.upsert_node(node_id, ["SCCM_Secret"], properties=props)
    logger.debug(
        f"Created SCCM_Secret node: {node_id} (type={secret_type}, site={site_code})"
    )
    return node_id
