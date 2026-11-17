# PyInstaller spec for macOS (.app) and Windows (.exe).
# Build from the repository root:  pyinstaller packaging/coldperimeter.spec
# -*- mode: python -*-

import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
PKG = ROOT / "coldperimeter"

datas = [
    (str(PKG / "gui" / "static"), "coldperimeter/gui/static"),
    (str(PKG / "report" / "locales"), "coldperimeter/report/locales"),
    (str(PKG / "report" / "templates"), "coldperimeter/report/templates"),
    (str(PKG / "fingerprint" / "signatures"), "coldperimeter/fingerprint/signatures"),
]

hiddenimports = (
    collect_submodules("coldperimeter")
    + collect_submodules("uvicorn")
    + collect_submodules("webview")
)

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hiddenimports,
    excludes=["tkinter", "pytest", "tests"],
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ColdPerimeter",
    console=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="ColdPerimeter", upx=False)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="ColdPerimeter.app",
        bundle_identifier="org.coldperimeter.app",
        info_plist={
            "CFBundleShortVersionString": "0.1.0",
            "NSHighResolutionCapable": True,
            "NSLocalNetworkUsageDescription":
                "ColdPerimeter scans the local network to find refrigeration controllers.",
        },
    )
