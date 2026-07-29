"""SCCMSite convert: versionCVEs populated from the site version via cve_table."""
from openhound_sccm.models.sccm_site import SCCMSite


def test_known_vulnerable_version_populates_version_cves():
    node = SCCMSite(site_code="PS1", version="9135").as_node  # 2503 base -> all CVEs
    assert node is not None
    assert node.properties.versionCVEs, "expected CVEs for a base 2503 build"
    assert all(c.startswith("CVE-") for c in node.properties.versionCVEs)


def test_no_version_leaves_version_cves_none():
    node = SCCMSite(site_code="PS1", version=None).as_node
    assert node is not None
    assert node.properties.versionCVEs is None
