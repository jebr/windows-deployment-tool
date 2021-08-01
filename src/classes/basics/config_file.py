from base_functions import BaseFunctions
import os
import json

powershell = BaseFunctions.powershell

username = powershell(['$env:username']).rstrip()
folder_path = fr'C:\Users\{username}\AppData\Local\Programs\WDT'
config_file = fr'{folder_path}\wdt_config.json'


def create_config_file():
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    if not os.path.exists(config_file):
        with open(config_file, 'w') as file:
            pass


def write_default_config():
    if os.path.exists(config_file):
        if os.stat(config_file).st_size == 0:
            with open('../../config.json') as cfg:
                config = json.load(cfg)

            with open(config_file, 'w') as cf:
                json.dump(config, cf, indent=2)


create_config_file()
write_default_config()

