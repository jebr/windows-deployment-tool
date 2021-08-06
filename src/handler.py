import os
from classes.productkey.windows_productkey import WindowsProductKey
from classes.system.system_information import HardWareInformation
from classes.system.system_information import WindowsInformation
from classes.system_checks.system_checks import SystemChecks
import classes.config.config as config
import classes.basics.base_functions as basics
from classes.app_settings.app_settings import productkey_file_location
import getpass
import webbrowser


def current_user():
    return getpass.getuser()


def wdt_current_version():
    return float(config.get_application_config_subject_item("application_information", "version"))


def open_releases_website():
    webbrowser.open(config.get_application_config_subject_item("application_information", "releases_website"))


def open_documentation_website():
    webbrowser.open(config.get_application_config_subject_item("application_information", "documentation_website"))


@basics.thread
def initial_run():
    config.create_config_file()
    if not os.path.exists(productkey_file_location):
        config.write_system_information()






