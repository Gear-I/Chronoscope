# PyInstaller spec for the Windows build: one folder holding Chronoscope.exe (the desktop
# app) and chronoscope-cli.exe (the command line), sharing one copy of Python, Qt and the
# parser libraries. Build from the repository root, with Chronoscope and all its extras
# installed:
#
#   pyinstaller --noconfirm packaging/windows/chronoscope.spec
#
# The result is dist/Chronoscope/.

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

HERE = Path(SPECPATH)
ROOT = HERE.parent.parent
ICON = str(ROOT / "src" / "chronoscope" / "resources" / "icon.png")

datas = collect_data_files("chronoscope")
datas += copy_metadata("chronoscope-forensics")
# Parsers import their optional libraries lazily, so PyInstaller can't see them.
hiddenimports = (
    collect_submodules("chronoscope")
    + collect_submodules("py7zr")
    + collect_submodules("Evtx")
    + ["pytsk3", "pyewf"]
)
# PySide6 ships many modules the app doesn't use; leave out the large ones.
excludes = [
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.Qt3DCore",
    "PySide6.QtMultimedia",
    "PySide6.QtPdf",
    "tkinter",
]


def analysis(script):
    return Analysis(
        [str(HERE / script)],
        pathex=[str(ROOT / "src")],
        datas=datas,
        hiddenimports=hiddenimports,
        excludes=excludes,
    )


gui = analysis("gui_main.py")
cli = analysis("cli_main.py")

gui_exe = EXE(
    PYZ(gui.pure),
    gui.scripts,
    exclude_binaries=True,
    name="Chronoscope",
    icon=ICON,
    console=False,
)
cli_exe = EXE(
    PYZ(cli.pure),
    cli.scripts,
    exclude_binaries=True,
    name="chronoscope-cli",
    icon=ICON,
    console=True,
)

COLLECT(
    gui_exe,
    gui.binaries,
    gui.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    name="Chronoscope",
)
