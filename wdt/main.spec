# -*- mode: python ; coding: utf-8 -*-
# python -m PyInstaller main.spec --onefile

block_cipher = None


a = Analysis(['main.py'],
             pathex=['C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt'],
             binaries=[],
             datas=[('C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt\\data\\wdt.ico', '.'),
                    ('C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt\\ui_files\\main_window.ui', '.'),
                    ('C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt\\ui_files\\about_popup.ui', '.'),
                    ('C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt\\ui_files\\hostname_help_popup.ui', '.'),
                    ('C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt\\ui_files\\licence_popup.ui', '.'),
                    ('C:\\Users\\Jeroen\\OneDrive\\development\\projects\\wdt\\wdt\\ui_files\\settings_popup.ui', '.')],
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
          console=False , uac_admin=True, uac_uiaccess=True)
