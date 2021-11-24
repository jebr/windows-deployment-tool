import getpass
from ..basics.base_functions import resource_path

# Application information
wdt_current_version = float(3.0)
wdt_developers = ["Jeroen Brauns", "Niels van den Bos"]
wdt_release_website = "https://github.com/jebr/windows-deployment-tool/releases"
wdt_documentation_website = "https://windows-deployment-tool.readthedocs.io/"
wdt_version_file = 'https://raw.githubusercontent.com/jebr/windows-deployment-tool/master/version.txt'

# Application paths
win_current_user = getpass.getuser()
wdt_folder_path = fr'C:\Users\{win_current_user}\AppData\Local\Programs\WDT'
config_file_location = fr'{wdt_folder_path}\wdt_config.json'
productkey_file_location = fr'{wdt_folder_path}\productkey.json'
log_file_location = fr'{wdt_folder_path}\wdt.log'

# Application external files
ui_main_window = resource_path('resources/ui/main_window.ui')
ui_hostname_window = resource_path('resources/ui/hostname_help_dialog.ui')
ui_info_window = resource_path('resources/ui/info_dialog.ui')
ui_license_window = resource_path('resources/ui/license_dialog.ui')
ui_logging_window = resource_path('resources/ui/wdt_logging_dialog.ui')
ui_admin_window = resource_path('resources/ui/admin_dialog.ui')
ui_password_window = resource_path('resources/ui/password_help_dialog.ui')
ui_username_window = resource_path('resources/ui/username_help_dialog.ui')
icon_window = resource_path('icons/wdt.ico')
icon_transparant_image = resource_path('icons/transparent.png')
icon_circle_info = resource_path('icons/circle-info.png')
icon_circle_check = resource_path('icons/circle-check.png')
icon_heijmans_logo = resource_path('icons/heijmans-logo.jpg')
icon_heijmans_logo_square = resource_path('icons/heijmans-vierkant.bmp')
icon_workstation = resource_path('icons/icon_workstation')
secpol_new = resource_path('resources/security/secpol_new.inf')
energy_config_on = resource_path('resources/energy/energy-full.pow')
energy_config_lock = resource_path('resources/energy/energy-auto-lock.pow')
energy_config_default = resource_path('resources/energy/energy-default.pow')
license_file = resource_path('resources/license/license.txt')
wdt_table_users = resource_path('wdt_table_users.py')

