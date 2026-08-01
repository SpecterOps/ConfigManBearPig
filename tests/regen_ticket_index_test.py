"""Ticket-index generator, and a guard that the committed index is current.

dev/ is not an importable package, so the module is loaded by path.

The last test is the point of the whole file: `.tickets/_TICKETS-BY-STATUS.md` is
generated, `gtk` has no subcommand that rebuilds it, and a stale index is invisible
until someone reads it and believes it. Running the generator's --check logic here
turns "somebody forgot to regenerate" into a failing test.
"""
import importlib.util
import pathlib
import sys

_REPO = pathlib.Path(__file__).resolve().parents[1]
_PATH = _REPO / "dev" / "regen_ticket_index.py"
_SPEC = importlib.util.spec_from_file_location("regen_ticket_index", _PATH)
assert _SPEC and _SPEC.loader
regen = importlib.util.module_from_spec(_SPEC)
sys.modules["regen_ticket_index"] = regen
_SPEC.loader.exec_module(regen)


def _write(dirpath, name, *, status="open", priority=2, ttype="task",
           tags="[a, b]", title="A title"):
    (dirpath / name).write_text(
        f"---\nid: {name.removesuffix('.md')}\nstatus: {status}\n"
        f"type: {ttype}\npriority: {priority}\ntags: {tags}\n---\n\n# {title}\n",
        encoding="utf-8")


def test_parse_ticket_reads_frontmatter_and_title(tmp_path):
    _write(tmp_path, "con-1.md", status="closed", priority=1, ttype="bug",
           tags="[sccm, ldap]", title="Something broke")
    rec = regen.parse_ticket(tmp_path / "con-1.md")
    assert rec["id"] == "con-1"
    assert rec["status"] == "closed"
    assert rec["type"] == "bug"
    assert rec["priority"] == 1
    assert rec["tags"] == ["sccm", "ldap"]
    assert rec["title"] == "Something broke"


def test_parse_ticket_returns_none_without_frontmatter(tmp_path):
    (tmp_path / "notes.md").write_text("# Just a heading\n", encoding="utf-8")
    assert regen.parse_ticket(tmp_path / "notes.md") is None


def test_load_tickets_skips_underscore_files(tmp_path):
    _write(tmp_path, "con-1.md")
    (tmp_path / "_TICKETS-BY-STATUS.md").write_text("# generated\n", encoding="utf-8")
    assert [r["id"] for r in regen.load_tickets(tmp_path)] == ["con-1"]


def test_render_buckets_and_counts(tmp_path):
    _write(tmp_path, "con-a.md", status="open")
    _write(tmp_path, "con-b.md", status="closed")
    _write(tmp_path, "con-c.md", status="in_progress")
    out = regen.render_index(regen.load_tickets(tmp_path))
    assert "**3 tickets**" in out
    assert "1 in progress" in out and "1 open" in out and "1 closed" in out
    assert "## In progress (1)" in out
    # section order is fixed: in progress, then open, then closed
    assert out.index("## In progress") < out.index("## Open") < out.index("## Closed")


def test_rows_sort_by_priority_then_id(tmp_path):
    _write(tmp_path, "con-zzz.md", priority=1)
    _write(tmp_path, "con-aaa.md", priority=2)
    _write(tmp_path, "con-bbb.md", priority=1)
    out = regen.render_index(regen.load_tickets(tmp_path))
    assert out.index("con-bbb") < out.index("con-zzz") < out.index("con-aaa")


def test_untagged_ticket_renders_an_em_dash(tmp_path):
    _write(tmp_path, "con-1.md", tags="[]")
    assert "| — |" in regen.render_index(regen.load_tickets(tmp_path))


def test_long_titles_are_truncated(tmp_path):
    _write(tmp_path, "con-1.md", title="x" * 400)
    out = regen.render_index(regen.load_tickets(tmp_path))
    row = next(line for line in out.splitlines() if "con-1" in line)
    title = row.split("|")[4].strip()
    assert len(title) == regen.TITLE_MAX and title.endswith("...")


def test_a_pipe_in_a_title_cannot_break_the_table(tmp_path):
    _write(tmp_path, "con-1.md", title="before | after")
    row = next(line for line in regen.render_index(regen.load_tickets(tmp_path)).splitlines()
               if "con-1" in line)
    assert r"before \| after" in row
    # A five-column row has six structural pipes (leading, four separators, trailing);
    # the escaped one in the title is the seventh and must not add a column.
    assert row.count("|") == 7
    assert len(row.split(r"\|")[0].split("|")) == 5   # nothing split the row early


def test_committed_index_is_up_to_date():
    """Fails when a ticket status changed without regenerating the index.

    Fix by running: uv run python dev/regen_ticket_index.py
    """
    tickets = _REPO / ".tickets"
    expected = regen.render_index(regen.load_tickets(tickets))
    actual = (tickets / regen.INDEX_NAME).read_text(encoding="utf-8")
    assert actual == expected, (
        "`.tickets/_TICKETS-BY-STATUS.md` is stale -- run "
        "`uv run python dev/regen_ticket_index.py`"
    )
