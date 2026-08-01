def test_models_and_main_import():
    import importlib
    importlib.import_module("openhound_sccm.models")
    importlib.import_module("openhound_sccm.main")   # registers @app.collect/@app.preproc/@app.convert
