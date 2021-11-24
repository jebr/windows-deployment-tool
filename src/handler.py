import os
import json
import getpass
import webbrowser
from classes.productkey.windows_productkey import WindowsProductKey
from classes.system.system_information import HardWareInformation, WindowsInformation
from classes.system_checks.system_checks import SystemChecks
from classes.basics.logger import Logger
import classes.config.config as config
from classes.basics.base_functions import thread
from classes.app_settings.app_settings import *
from classes.system_checks.system_checks import *
from classes.app_functions.app_functions import *

logger = Logger(log_file_location)


def current_user():
    return getpass.getuser()


# def handler.wdt_current_version():
#     return float(config.get_application_config_subject_item("application_information", "version"))


def open_releases_website():
    webbrowser.open(wdt_release_website)


def open_documentation_website():
    webbrowser.open(wdt_documentation_website)


@thread
def initial_run():
    config.create_config_file()
    if not os.path.exists(productkey_file_location):
        config.write_system_information()


def get_application_config_subject_item(subject: str, item: str) -> str:
    """ Get information about a subject item of the config file """
    if os.path.exists(config_file_location):
        with open(config_file_location) as cfg:
            config = json.load(cfg)
        return config[subject][item]
    else:
        return f"Applciation information not found at {config_file_location}"








