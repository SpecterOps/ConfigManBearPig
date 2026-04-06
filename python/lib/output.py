"""
Output generation for ConfigManBearPig.

Translated from PowerShell output functions:
- Export-BloodHoundData (lines 9681-9846)
- New-StreamingBloodHoundWriter / Write-BloodHoundNode / Write-BloodHoundEdge (lines 9523-9679)
- Close-BloodHoundWriter
- Show-CurrentFileSize / Test-FileSizeLimit

Produces BloodHound OpenGraph JSON files and ZIP archive.
"""

import json
import logging
import os
import time
import zipfile
from datetime import datetime
from typing import Any, Optional

from lib.graph import GraphStore

logger = logging.getLogger("ConfigManBearPig")

# Schema URL matching PowerShell output
SCHEMA_URL = (
    "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/"
    "refs/heads/main/bloodhound-opengraph.schema.json"
)

# Seed data UUID (matching PowerShell exactly)
SEED_ID = "9c3a1f7a-1d6b-4d87-b61b-1c3b7a9e4f01"

# All edge kinds for seed_data.json (matching PowerShell exactly, lines 9792-9827)
SEED_EDGE_KINDS = [
    "LocalAdminRequired",
    "CoerceAndRelayToAdminService",
    "CoerceAndRelayToMSSQL",
    "CoerceAndRelayToSMB",
    "HasSession",
    "MSSQL_Contains",
    "MSSQL_ControlDB",
    "MSSQL_ControlServer",
    "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS",
    "MSSQL_GetTGS",
    "MSSQL_HasLogin",
    "MSSQL_HostFor",
    "MSSQL_IsMappedTo",
    "MSSQL_LinkedAsAdmin",
    "MSSQL_MemberOf",
    "MSSQL_ServiceAccountFor",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo",
    "SCCM_AllPermissions",
    "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions",
    "SCCM_AssignSpecificPermissions",
    "SCCM_Contains",
    "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser",
    "SCCM_HasClient",
    "SCCM_HasCurrentUser",
    "SCCM_HasMember",
    "SCCM_HasCollectionVar",
    "SCCM_HasNetworkAccessAccount",
    "SCCM_HasPrimaryUser",
    "SCCM_HasTaskSequence",
    "SCCM_HasStoredAccount",
    "SCCM_IsAssigned",
    "SCCM_IsMappedTo",
]


class StreamingBloodHoundWriter:
    """
    Streaming JSON writer that matches the PowerShell streaming output format.

    Translated from PowerShell New-StreamingBloodHoundWriter, Write-BloodHoundNode,
    Write-BloodHoundEdge, Close-BloodHoundWriter (lines 9523-9679).
    """

    def __init__(self, file_path: str, include_source_kind: bool = True):
        self.file_path = os.path.abspath(file_path)
        self.include_source_kind = include_source_kind
        self.node_count = 0
        self.edge_count = 0
        self._first_node = True
        self._first_edge = True

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

        # Open file
        self._file = open(self.file_path, "w", encoding="utf-8")
        self._write_header()
        logger.info(f"Created output file: {self.file_path}")

    def _write_header(self) -> None:
        """Write the JSON header."""
        self._file.write("{\n")
        self._file.write(
            f'  "$schema": "{SCHEMA_URL}",\n'
        )
        if self.include_source_kind:
            self._file.write('  "metadata": {\n')
            self._file.write('    "source_kind": "SCCM_Base"\n')
            self._file.write("  },\n")
        self._file.write('  "graph": {\n')
        self._file.write('    "nodes": [\n')
        self._file.flush()

    def write_node(self, node: dict[str, Any]) -> None:
        """Write a single node to the output."""
        if not self._first_node:
            self._file.write(",\n")
        self._first_node = False
        self.node_count += 1

        json_str = json.dumps(node, separators=(",", ":"))
        self._file.write(f"      {json_str}")
        self._file.flush()

    def write_edge(self, edge: dict[str, Any]) -> None:
        """Write a single edge to the output."""
        # If this is the first edge, close nodes array and start edges array
        if self.edge_count == 0 and self.node_count > 0:
            self._file.write("\n")
            self._file.write("    ],\n")
            self._file.write('    "edges": [\n')
            self._file.flush()

        if not self._first_edge:
            self._file.write(",\n")
        self._first_edge = False
        self.edge_count += 1

        json_str = json.dumps(edge, separators=(",", ":"))
        self._file.write(f"      {json_str}")
        self._file.flush()

    def close(self) -> None:
        """Close the writer and finalize JSON structure."""
        try:
            # If we wrote nodes but no edges, close nodes and add empty edges
            if self.node_count > 0 and self.edge_count == 0:
                self._file.write("\n")
                self._file.write("    ],\n")
                self._file.write('    "edges": [\n')

            # Close the structure
            if self.edge_count > 0 or self.node_count > 0:
                self._file.write("\n")
            self._file.write("    ]\n")
            self._file.write("  }\n")
            self._file.write("}\n")
            self._file.flush()
            self._file.close()

            # Report file size
            file_size = os.path.getsize(self.file_path)
            size_str = _format_size(file_size)
            logger.info(f"Output written to {self.file_path}")
            logger.info(f"File size: {size_str}")
        except Exception as e:
            logger.error(f"Error closing BloodHound file: {e}")


def _format_size(size_bytes: int) -> str:
    """Format byte size to human-readable string."""
    if size_bytes >= 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    elif size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes} bytes"


def _generate_seed_data() -> dict[str, Any]:
    """
    Generate seed_data.json content.

    Translated from PowerShell lines 9788-9846.
    """
    seed_ref = {"value": SEED_ID}
    return {
        "metadata": {"source_kind": "SCCM_Seed"},
        "graph": {
            "nodes": [
                {
                    "kinds": ["IgnoreMe"],
                    "id": SEED_ID,
                    "properties": {"name": "IgnoreMe"},
                }
            ],
            "edges": [
                {"kind": kind, "start": seed_ref, "end": seed_ref}
                for kind in SEED_EDGE_KINDS
            ],
        },
    }


def generate_custom_nodes_json() -> dict[str, Any]:
    """
    Generate custom nodes type definitions for BloodHound API.

    Translated from PowerShell OutputFormat=CustomNodes (lines 9967-10058).
    """
    return {
        "custom_types": {
            "SCCM_Site": {
                "icon": {"color": "#67ebf0", "name": "city", "type": "font-awesome"}
            },
            "SCCM_AdminUser": {
                "icon": {"color": "#558eea", "name": "user-gear", "type": "font-awesome"}
            },
            "SCCM_SecurityRole": {
                "icon": {"color": "#9852ed", "name": "users-gear", "type": "font-awesome"}
            },
            "SCCM_Collection": {
                "icon": {"color": "#fff82e", "name": "sitemap", "type": "font-awesome"}
            },
            "SCCM_ClientDevice": {
                "icon": {"color": "#f59b42", "name": "desktop", "type": "font-awesome"}
            },
            "MSSQL_DatabaseUser": {
                "icon": {"color": "#f5ef42", "name": "user", "type": "font-awesome"}
            },
            "MSSQL_Login": {
                "icon": {"color": "#dd42f5", "name": "user-gear", "type": "font-awesome"}
            },
            "MSSQL_DatabaseRole": {
                "icon": {"color": "#f5a142", "name": "users", "type": "font-awesome"}
            },
            "MSSQL_Database": {
                "icon": {"color": "#f54242", "name": "database", "type": "font-awesome"}
            },
            "MSSQL_Server": {
                "icon": {"color": "#42b9f5", "name": "server", "type": "font-awesome"}
            },
            "MSSQL_ServerRole": {
                "icon": {"color": "#6942f5", "name": "users-gear", "type": "font-awesome"}
            },
        }
    }


def export_bloodhound_data(
    graph: GraphStore,
    temp_dir: Optional[str] = None,
    zip_dir: Optional[str] = None,
    file_size_limit: str = "1GB",
) -> Optional[str]:
    """
    Export collected data to BloodHound OpenGraph JSON files and ZIP.

    Translated from PowerShell Export-BloodHoundData (lines 9681-9846).

    Separates output into:
    - computers.json: Computer nodes (no source_kind metadata)
    - groups.json: Group nodes (no source_kind metadata)
    - users.json: User nodes (no source_kind metadata)
    - sccm.json: SCCM-specific nodes + ALL edges (with source_kind)
    - seed_data.json: Edge kind declarations

    Args:
        graph: GraphStore containing all nodes and edges
        temp_dir: Directory for temp JSON files
        zip_dir: Directory for final ZIP file
        file_size_limit: Maximum cumulative file size

    Returns:
        Path to the ZIP file, or None on failure
    """
    nodes = graph.nodes
    edges = graph.edges

    # Report statistics
    total_targets = len(nodes)  # Approximate
    logger.info(f"Total nodes created: {len(nodes)}")
    logger.info(f"Total edges created: {len(edges)}")

    if not nodes and not edges:
        logger.warning("No nodes or edges were created, skipping BloodHound export")
        return None

    # Set up temp directory
    if not temp_dir:
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        temp_dir = os.path.join(
            os.environ.get("TMPDIR", os.environ.get("TEMP", "/tmp")),
            f"ConfigManBearPig-{timestamp}",
        )

    os.makedirs(temp_dir, exist_ok=True)
    logger.info("Writing BloodHound data...")

    output_files: list[str] = []

    # Separate nodes by type
    computer_nodes = [n for n in nodes if "Computer" in n.get("kinds", [])]
    group_nodes = [n for n in nodes if "Group" in n.get("kinds", [])]
    user_nodes = [n for n in nodes if "User" in n.get("kinds", [])]
    sccm_nodes = [
        n for n in nodes
        if "Computer" not in n.get("kinds", [])
        and "Group" not in n.get("kinds", [])
        and "User" not in n.get("kinds", [])
    ]

    # Write base domain object files (no source_kind)
    base_files = {
        "computers.json": computer_nodes,
        "groups.json": group_nodes,
        "users.json": user_nodes,
    }

    for filename, file_nodes in base_files.items():
        if not file_nodes:
            continue

        file_path = os.path.join(temp_dir, filename)
        output_files.append(file_path)

        logger.info(
            f"Writing {len(file_nodes)} {filename.replace('.json', '')} nodes to: {file_path}"
        )

        writer = StreamingBloodHoundWriter(file_path, include_source_kind=False)
        try:
            for node in file_nodes:
                writer.write_node(node)
            writer.close()
        except Exception as e:
            logger.error(f"Failed to write {filename}: {e}")
            writer.close()

    # Write SCCM nodes + all edges to sccm.json
    sccm_file = os.path.join(temp_dir, "sccm.json")
    output_files.append(sccm_file)

    logger.info(f"Writing to file: {sccm_file}")
    writer = StreamingBloodHoundWriter(sccm_file, include_source_kind=True)
    try:
        for node in sccm_nodes:
            writer.write_node(node)
        for edge in edges:
            writer.write_edge(edge)
        logger.info(
            f"Wrote {len(sccm_nodes)} SCCM nodes and {len(edges)} edges"
        )
        writer.close()
    except Exception as e:
        logger.error(f"Failed to write sccm.json: {e}")
        writer.close()

    # Write seed_data.json
    seed_path = os.path.join(temp_dir, "seed_data.json")
    seed_data = _generate_seed_data()
    with open(seed_path, "w", encoding="utf-8") as f:
        json.dump(seed_data, f, separators=(",", ":"))
    output_files.append(seed_path)

    # Report file sizes
    total_size = 0
    logger.info("Output files created:")
    for file_path in output_files:
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            total_size += file_size
            logger.info(f"  {file_path} - {_format_size(file_size)}")

    logger.info(f"Total size: {_format_size(total_size)} across {len(output_files)} files")

    # Create ZIP archive
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    zip_filename = f"bloodhound-sccm-{timestamp}.zip"

    if zip_dir:
        if os.path.isdir(zip_dir):
            zip_path = os.path.join(zip_dir, zip_filename)
        else:
            zip_path = zip_dir
    else:
        zip_path = os.path.join(os.getcwd(), zip_filename)

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in output_files:
                if os.path.exists(file_path):
                    arcname = os.path.basename(file_path)
                    logger.info(f"  Adding: {arcname}")
                    zf.write(file_path, arcname)

        # Report ZIP info
        if os.path.exists(zip_path):
            zip_size = os.path.getsize(zip_path)
            logger.info(
                f"ZIP archive created successfully: {zip_filename} ({_format_size(zip_size)})"
            )
            if total_size > 0:
                ratio = (1 - zip_size / total_size) * 100
                logger.info(f"Compression ratio: {ratio:.1f}% reduction")

            # Delete original files
            logger.info("Deleting original files...")
            deleted = 0
            for file_path in output_files:
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        deleted += 1
                    except OSError as e:
                        logger.warning(f"Failed to delete: {os.path.basename(file_path)} - {e}")

            if deleted > 0:
                logger.info(f"Successfully deleted {deleted} original files")

            # Clean up temp dir if empty
            try:
                os.rmdir(temp_dir)
            except OSError:
                pass

            logger.info(f"Final output: {os.path.abspath(zip_path)}")
            return os.path.abspath(zip_path)

    except Exception as e:
        logger.error(f"Error creating ZIP archive: {e}")
        logger.warning("Original files have been preserved")

    return None
