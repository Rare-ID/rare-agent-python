from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent

for path in (
    ROOT / "src",
    WORKSPACE / "rare-identity-core" / "libs",
    WORKSPACE / "rare-identity-core" / "services",
    WORKSPACE / "rare-thirdparty-moltbook-example" / "apps",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
