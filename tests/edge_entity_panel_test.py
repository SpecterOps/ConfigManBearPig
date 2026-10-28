"""Check that every authored custom edge has readable schema-based help."""

import json
import re
from pathlib import Path

from openhound_sccm.edge_help import EDGE_HELP

ROOT = Path(__file__).resolve().parents[1]


def test_all_authored_edges_have_complete_markdown_sections():
    """Missing help sections or broken commands should fail before release."""
    covered = set()
    for name in ("schema_SCCM.json", "schema_MSSQL.json"):
        packaged = ROOT / "src/openhound_sccm" / name
        assert packaged.read_bytes() == (ROOT / "extension" / name).read_bytes()
        schema = json.loads(packaged.read_text(encoding="utf-8"))
        for edge in schema["relationship_kinds"]:
            if edge["name"] not in EDGE_HELP:
                # Additional MSSQL kinds are outside this collector's authored help.
                continue
            covered.add(edge["name"])
            authored = {
                {"windowsAbuse": "windows_abuse", "linuxAbuse": "linux_abuse"}.get(key, key): value
                for key, value in EDGE_HELP[edge["name"]].as_fields().items()
            }
            sections = edge["info"]
            assert set(sections) == set(authored)
            positions = [section["position"] for section in sections.values()]
            assert positions == sorted(set(positions))
            for key, value in authored.items():
                assert re.fullmatch(r"[a-z0-9_-]{1,128}", key)
                content = sections[key]["markdown"]["content"]
                assert content.strip()
                assert content.count("```text") * 2 == content.count("```")
                assert "{{" not in content
                # Literal placeholders must be code, or Markdown treats them as HTML.
                prose = re.sub(r"```.*?```|`[^`]*`", "", content, flags=re.S)
                assert not re.search(r"<[A-Za-z/!][^>]*>", prose), (edge["name"], key)
                if isinstance(value, list):
                    assert content.splitlines() == [f"- [{url}]({url})" for url in value]
                else:
                    # All original commands survive verbatim, whether inline or fenced.
                    for command in re.findall(r"`([^`]+)`", value):
                        assert command in content
                    assert not re.search(r"(?m)^`[^`]+`$", content)
    assert covered == set(EDGE_HELP)


def test_mssql_schema_uses_server_environment_kind():
    schema = json.loads((ROOT / "src/openhound_sccm/schema_MSSQL.json").read_text(encoding="utf-8"))
    assert schema["environments"][0]["environment_kind"] == "MSSQL_Server"
