import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

import pytest


os.environ.setdefault(
    "RUNTIME__LOG_PATH",
    str(Path(__file__).resolve().parents[1] / "logs"),
)


@pytest.fixture(scope="session")
def render_entity_panel(
    tmp_path_factory: pytest.TempPathFactory,
) -> Callable[[dict[str, str], dict[str, object]], dict[str, str]]:
    """Render supplied schema templates with a shared, test-only Go helper."""
    go_binary = os.environ.get("CMBP_GO_BINARY") or shutil.which("go")
    if not go_binary:
        pytest.skip("Set CMBP_GO_BINARY or put Go on PATH to render templates.")
    # A configured compiler must compile successfully; errors are not skipped.
    root = Path(__file__).resolve().parents[1]
    directory = tmp_path_factory.mktemp("entity-panel-renderer")
    executable = directory / ("render.exe" if os.name == "nt" else "render")
    # Reuse Go's standard-library cache rather than rebuilding it for each panel.
    environment = dict(os.environ, GO111MODULE="off", GOTOOLCHAIN="local")
    result = subprocess.run(
        [
            go_binary,
            "build",
            "-o",
            str(executable),
            str(root / "tests/support/render_entity_panel.go"),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr

    def render(
        templates: dict[str, str], properties: dict[str, object]
    ) -> dict[str, str]:
        """Run the actual Go template engine and validate its JSON response."""
        result = subprocess.run(
            [str(executable)],
            input=json.dumps({"Templates": templates, "Properties": properties}),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        # JSON from the separate test process is the one untyped boundary.
        output = json.loads(result.stdout)
        assert isinstance(output, dict)
        assert all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in output.items()
        )
        return output

    return render


@pytest.fixture
def table_rows() -> Callable[[str, list[str]], list[str]]:
    """Check table columns and reject blank lines that would split the table."""

    def rows(content: str, headers: list[str]) -> list[str]:
        text = content.strip()
        if not text:
            # An empty property array must produce no orphan table header.
            return []
        lines = text.splitlines()
        assert lines[0] == "| " + " | ".join(headers) + " |"
        assert lines[1] == "| " + " | ".join("---" for _ in headers) + " |"
        assert len(lines) > 2
        for line in lines[2:]:
            assert line.startswith("| ") and line.endswith(" |"), line
            assert len(line.split("|")) == len(headers) + 2, line
        return lines[2:]

    return rows
