"""Unit tests for the shared transport-neutral row-shaping atoms."""
from openhound_sccm.collectors import sms_rows as s


def test_snake_handles_acronyms():
    assert s._snake("SiteCode") == "site_code"
    assert s._snake("AADDeviceID") == "aad_device_id"
    assert s._snake("ThisSiteCode") == "this_site_code"
    assert s._snake("SMSID") == "smsid"


def test_row_snakes_and_tags_and_drops_odata():
    row = s._row("WMI-SMS_Site", "PS1",
                 {"SiteCode": "PS1", "@odata.type": "x", "BuildNumber": "9000"})
    assert row == {"source": "WMI-SMS_Site", "source_site_code": "PS1",
                   "site_code": "PS1", "build_number": "9000"}


def test_row_keep_whitelists_with_tuple():
    row = s._row("src", "PS1", {"RoleName": "X", "LazyJunk": "y"}, keep=s.ROLE_COLUMNS)
    assert "role_name" in row and "lazy_junk" not in row


def test_row_drop_and_extra():
    row = s._row("src", "PS1", {"SiteCode": "PS1", "Props": [1, 2]},
                 drop={"Props"}, extra={"site_guid": "{G}"})
    assert row["site_guid"] == "{G}" and "props" not in row


def test_prop_reads_named_value():
    props = [{"PropertyName": "siteGUID", "Value1": "{G}"},
             {"PropertyName": "SQLServicePort", "Value": 1433}]
    assert s._prop(props, "siteGUID", "Value1") == "{G}"
    assert s._prop(props, "SQLServicePort", "Value") == 1433
    assert s._prop(props, "missing") is None
    assert s._prop(None, "siteGUID") is None


def test_odata_select_renders_select_clause():
    assert s.odata_select(("A", "B", "C")) == "$select=A,B,C"
    assert s.odata_select(s.COLLECTION_MEMBER_COLUMNS) == "$select=CollectionID,ResourceID,SiteCode"
