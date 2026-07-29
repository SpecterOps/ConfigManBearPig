"""Task 3 (D3): the `_mark_assumed` provenance-stamp helper.

Most of transforms.py builds nodes/edges via raw SQL (a Python dict helper can't
run mid-query), so Tasks 4/5 inline the equivalent three columns directly into
their INSERTs rather than calling this function. `_mark_assumed` exists for any
Python-side row construction that needs the same stamp, and its slug algorithm
is the reference the SQL builders' hand-picked `Assumed-<Tag>` constants are
checked against for wording drift.
"""
from openhound_sccm.transforms import _mark_assumed


def test_marks_assumed_and_tags_source():
    out = _mark_assumed({"collectionSource": ["LDAP-CmRcService"]},
                        basis="CmRcService SPN; SCCM client not confirmed")
    assert out["assumed"] is True
    assert out["assumptionBasis"] == "CmRcService SPN; SCCM client not confirmed"
    assert "Assumed-CmRcService SPN; SCCM client not confirmed" not in out["collectionSource"]  # tag is slugged, not raw
    assert any(s.startswith("Assumed-") for s in out["collectionSource"])
    assert "LDAP-CmRcService" in out["collectionSource"]  # preserved


def test_idempotent():
    a = _mark_assumed({}, basis="x")
    b = _mark_assumed(dict(a), basis="x")
    assert b["collectionSource"].count(next(s for s in b["collectionSource"] if s.startswith("Assumed-"))) == 1
