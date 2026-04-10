# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['stig_assessor\\ui\\cli.py'],
    pathex=[],
    binaries=[],
    datas=[('stig_assessor/ui/web/assets', 'stig_assessor/ui/web/assets')],
    hiddenimports=['tkinter', 'sqlite3'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='STIG_Assessor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
