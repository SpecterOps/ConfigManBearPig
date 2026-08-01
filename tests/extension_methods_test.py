from openhound.core.app import OpenHound
from dlt.extract.validation import PydanticValidator
from openhound_sccm.main import app as ext_module


def test_extension_is_openhound():
    assert isinstance(
        ext_module, OpenHound
    ), "Extension is not an instance of OpenHound"


def test_extensions_contains_collect():
    assert (
        ext_module.collector is not None
    ), "Extension does not contain @app.collect decorator"


def test_extensions_contains_convert():
    # Previously skipped as "convert phase not yet implemented". It is: `convert sccm` is
    # hand-registered on the framework's convert Typer group and `app.converter` is
    # assigned in main.py (the decorator exposes no flag-carrying seam, so the BloodHound
    # upload options forced the manual route). The skip outlived the reason.
    assert (
        ext_module.converter is not None
    ), "Extension does not assign app.converter"


def test_extension_resources_use_models(subtests):
    for dlt_resource in ext_module.dlt_resources:
        with subtests.test(resource=dlt_resource.name):
            columns = dlt_resource.columns
            validator = isinstance(dlt_resource.validator, PydanticValidator)
            assert (
                columns and validator
            ), f"Extension resource '{dlt_resource.name}' must have columns and use Pydantic models for validation"


def test_extension_resources_use_assets(subtests):
    for dlt_resource in ext_module.dlt_resources:
        with subtests.test(resource=dlt_resource.name):
            model_used = (
                dlt_resource.validator.model
                if isinstance(dlt_resource.validator, PydanticValidator)
                else None
            )
            is_model_an_asset = model_used in ext_module.assets
            assert (
                is_model_an_asset
            ), f"Extension resource '{dlt_resource.name}' must have a corresponding OpenGraph asset defined for its Pydantic model"
