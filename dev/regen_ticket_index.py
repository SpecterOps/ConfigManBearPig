"""Regenerate `.tickets/_TICKETS-BY-STATUS.md` from the ticket files.

The index is generated, not authored: the ticket `.md` files are the source of truth
and the index must be rebuilt after any status change rather than hand-edited. `gtk`
itself has no subcommand that does this, which is why the file drifted -- every agent
that changed a status either rewrote the table by hand or forgot.

    uv run python dev/regen_ticket_index.py            # rewrite the index
    uv run python dev/regen_ticket_index.py --check    # exit 1 if it is out of date

`--check` writes nothing, so it is safe in CI and in a test: it turns "somebody
forgot to regenerate" into a failure instead of a diff nobody notices.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_TICKETS = REPO_ROOT / ".tickets"
INDEX_NAME = "_TICKETS-BY-STATUS.md"
EMDASH = "—"

# Titles are capped so one runaway ticket cannot make the table unreadable. 150
# including the ellipsis matches what the previous generator produced, so
# regenerating does not churn every long row.
TITLE_MAX = 150

# Display order and heading text for each status bucket.
BUCKETS = (("in_progress", "In progress"), ("open", "Open"), ("closed", "Closed"))

HEADER = """# Tickets by status

Generated from the ticket files in this directory, which are the source of truth.
Regenerate after any status change rather than editing by hand.
`.gitattributes` marks this file `merge=ours`, which needs a one-time
`git config merge.ours.driver true` per clone.
"""


def parse_ticket(path: pathlib.Path) -> dict | None:
    """Read one ticket's frontmatter plus its first '# ' heading as the title.

    Returns None for a file with no YAML frontmatter -- the index itself, and any
    stray note someone drops in the directory.
    """
    text = path.read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    if not m:
        return None
    front, body = m.group(1), m.group(2)
    rec: dict = {"file": path.name, "tags": []}
    for line in front.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "tags":
            rec["tags"] = [t.strip() for t in value.strip("[]").split(",") if t.strip()]
        elif key in ("id", "status", "type"):
            rec[key] = value
        elif key == "priority":
            # A non-numeric priority sorts last rather than crashing the rebuild.
            rec[key] = int(value) if value.isdigit() else 9
    heading = re.search(r"^# (.+)$", body, re.MULTILINE)
    rec["title"] = heading.group(1).strip() if heading else rec.get("id", path.stem)
    rec.setdefault("priority", 9)
    rec.setdefault("type", "task")
    rec.setdefault("status", "open")
    rec.setdefault("id", path.stem)
    return rec


def load_tickets(tickets_dir: pathlib.Path) -> list[dict]:
    """Every ticket in *tickets_dir*, skipping underscore-prefixed generated files."""
    out = []
    for path in sorted(tickets_dir.glob("*.md")):
        if path.name.startswith("_"):
            continue
        rec = parse_ticket(path)
        if rec is None:
            print(f"skip (no frontmatter): {path.name}", file=sys.stderr)
            continue
        out.append(rec)
    return out


def _table(rows: list[dict]) -> list[str]:
    out = ["", "| Ticket | P | Type | Title | Tags |", "|---|---|---|---|---|"]
    for r in rows:
        tags = ", ".join(r["tags"]) if r["tags"] else EMDASH
        title = r["title"].replace("|", "\\|")
        if len(title) > TITLE_MAX:
            title = title[:TITLE_MAX - 3] + "..."
        out.append(f"| [`{r['id']}`]({r['file']}) | {r['priority']} | {r['type']} "
                   f"| {title} | {tags} |")
    return out


def render_index(tickets: list[dict]) -> str:
    """Build the whole index document from the parsed tickets."""
    buckets: dict[str, list[dict]] = {name: [] for name, _ in BUCKETS}
    for rec in tickets:
        buckets.setdefault(rec["status"], []).append(rec)
    # Priority first, then id, so the order is stable across rebuilds.
    for rows in buckets.values():
        rows.sort(key=lambda r: (r["priority"], r["id"].lower()))

    counts = {name: len(buckets[name]) for name, _ in BUCKETS}
    lines = [HEADER,
             f"**{len(tickets)} tickets** {EMDASH} {counts['in_progress']} in progress "
             f"· {counts['open']} open · {counts['closed']} closed"]
    for name, heading in BUCKETS:
        rows = buckets[name]
        lines.append(f"\n## {heading} ({len(rows)})")
        lines.extend(_table(rows))
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="regen_ticket_index",
        description="Regenerate .tickets/_TICKETS-BY-STATUS.md from the ticket files.")
    p.add_argument("tickets_dir", nargs="?", type=pathlib.Path, default=DEFAULT_TICKETS,
                   help="Directory of ticket .md files (default: the repo's .tickets/).")
    p.add_argument("--check", action="store_true",
                   help="Do not write; exit 1 if the index is out of date.")
    args = p.parse_args(argv)

    if not args.tickets_dir.is_dir():
        print(f"regen_ticket_index: no such directory: {args.tickets_dir}", file=sys.stderr)
        return 2

    tickets = load_tickets(args.tickets_dir)
    rendered = render_index(tickets)
    index = args.tickets_dir / INDEX_NAME

    if args.check:
        current = index.read_text(encoding="utf-8") if index.exists() else ""
        if current == rendered:
            print(f"{INDEX_NAME} is up to date ({len(tickets)} tickets)")
            return 0
        print(f"{INDEX_NAME} is OUT OF DATE -- run: uv run python dev/regen_ticket_index.py",
              file=sys.stderr)
        return 1

    index.write_text(rendered, encoding="utf-8")
    print(f"wrote {index} ({len(tickets)} tickets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
