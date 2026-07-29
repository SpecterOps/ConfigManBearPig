import os
from pathlib import Path


os.environ.setdefault(
    "RUNTIME__LOG_PATH",
    str(Path(__file__).resolve().parents[1] / "logs"),
)
