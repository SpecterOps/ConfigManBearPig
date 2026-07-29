"""extension.yaml is parsed by OpenHound on every run — keep it shipped, valid, and true.

OpenHound's CollectorManager.validate_metadata() resolves this file with
importlib.resources.files(<root package>) and feeds it to the Extension pydantic model.
A missing or invalid file is only an error log, not a crash, so nothing else in the test
suite would notice it rotting.
"""
from pathlib import Path

import yaml
from openhound.core.models.extension import Extension

import openhound_sccm

METADATA = Path(openhound_sccm.__file__).resolve().parent / "extension.yaml"


def test_extension_yaml_ships_inside_the_package():
    # Must sit next to the package's modules, or it is absent from the wheel.
    assert METADATA.is_file()


def test_extension_yaml_validates_against_openhounds_model():
    # The same call OpenHound makes on every run; raises ValidationError on drift.
    extension = Extension.from_yaml(METADATA)
    assert extension.name == "sccm"          # must match the entry-point key
    assert str(extension.version) == "2.0.0"


def test_extension_yaml_has_no_placeholder_metadata():
    data = yaml.safe_load(METADATA.read_text(encoding="utf-8"))
    assert "TBD" not in yaml.safe_dump(data)
    assert data["license"] == "Apache-2.0"
    assert data["homepage"].startswith("https://github.com/SpecterOps/ConfigManBearPig")
