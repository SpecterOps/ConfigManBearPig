import types
from openhound_sccm.collectors.local import collection_settings_rows


def test_collection_settings_single_row():
    ctx = types.SimpleNamespace(disable_possible_edges=True, enable_bad_opsec=False)
    rows = list(collection_settings_rows(ctx))
    assert rows == [{"disable_possible_edges": True, "enable_bad_opsec": False}]
