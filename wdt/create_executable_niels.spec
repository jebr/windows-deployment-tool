# -*- mode: python ; coding: utf-8 -*-
# python -m PyInstaller main.spec --onefile

block_cipher = None


a = Analysis(['main.py'],
             pathex=['C:\\Users\\niels\\OneDrive\\python\\projects\\wdt'],
             binaries=[],
             datas=[('C:\\Users\\niels\\OneDrive\\python\\projects\\wdt\\wdt.ui', '.'),
                    ('C:\\Users\\niels\\OneDrive\\python\\projects\\wdt\\images\\icons\\wdt.ico', '.')],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='main',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False,
          icon='wdt.ico' )
