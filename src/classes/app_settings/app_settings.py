import getpass

win_current_user = getpass.getuser()
wdt_folder_path = fr'C:\Users\{win_current_user}\AppData\Local\Programs\WDT'
config_file_location = fr'{wdt_folder_path}\wdt_config.json'
productkey_file_location = fr'{wdt_folder_path}\productkey.json'
log_file_location = fr'{wdt_folder_path}\wdt.log'

