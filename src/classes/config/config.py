import os
import json
from ..system.system_information import WindowsInformation, HardWareInformation
from ..productkey.windows_productkey import WindowsProductKey
from ..app_settings.app_settings import wdt_folder_path, config_file_location
from ..system_checks.system_checks import SystemChecks
from ..basics.base_functions import thread


def create_config_file():
    if not os.path.exists(wdt_folder_path):
        os.mkdir(wdt_folder_path)
    if not os.path.exists(config_file_location):
        with open(config_file_location, 'w') as file:
            pass
        write_default_config()


def write_default_config():
    with open('config.json') as cfg:
        config = json.load(cfg)

    with open(config_file_location, 'w') as cfg:
        json.dump(config, cfg, indent=2)

    write_system_information()


def write_system_information():
    os_version = WindowsInformation.os_version()
    windows_language = WindowsInformation.windows_language()
    domain_workgroup = WindowsInformation.domain_workgroup()
    computername = WindowsInformation.computername()
    windows_version = WindowsInformation.windows_version()
    windows_build = WindowsInformation.windows_build()
    pc_manufacturer = HardWareInformation.pc_manufacturer()
    pc_model = HardWareInformation.pc_model()
    pc_type = HardWareInformation.pc_type()
    pc_ram = HardWareInformation.pc_ram()
    pc_processor = HardWareInformation.pc_processor()
    pc_processor_cores = HardWareInformation.pc_processor_cores()
    pc_processor_logical_processors = HardWareInformation.pc_processor_logical_processors()
    pc_bios_version = HardWareInformation.pc_bios_version()
    pc_servicetag = HardWareInformation.pc_servicetag()
    power_options = SystemChecks.energy_check()
    ntp_client = SystemChecks.ntp_client_check()
    ntp_server = SystemChecks.ntp_server_check()
    wf_discovery = SystemChecks.wf_discovery_check()
    wf_icmp = SystemChecks.wf_icmp_check()

    change_config("system_information", "os_version", os_version)
    change_config("system_information", "windows_language", windows_language)
    change_config("system_information", "domain_workgroup", domain_workgroup)
    change_config("system_information", "computername", computername)
    change_config("system_information", "windows_version", windows_version)
    change_config("system_information", "windows_build", windows_build)
    change_config("system_information", "pc_manufacturer", pc_manufacturer)
    change_config("system_information", "pc_model", pc_model)
    change_config("system_information", "pc_type", pc_type)
    change_config("system_information", "pc_ram", pc_ram)
    change_config("system_information", "pc_processor", pc_processor)
    change_config("system_information", "pc_processor_cores", pc_processor_cores)
    change_config("system_information", "pc_processor_logical_processors", pc_processor_logical_processors)
    change_config("system_information", "pc_bios_version", pc_bios_version)
    change_config("system_information", "pc_servicetag", pc_servicetag)
    change_config("application_settings", "power_options", power_options)
    change_config("application_settings", "ntp_client", ntp_client)
    change_config("application_settings", "ntp_server", ntp_server)
    change_config("application_settings", "wf_discovery", wf_discovery)
    change_config("application_settings", "wf_icmp", wf_icmp)

    WindowsProductKey.write_product_key_to_file()
    windows_productkey = WindowsProductKey.extract_product_key()
    change_config("system_information", "windows_productkey", windows_productkey)


def get_application_config_subject(subject: str) -> dict:
    """ Get information about a subject of the config file """
    if os.path.exists(config_file_location):
        with open(config_file_location) as cfg:
            config = json.load(cfg)
        return config[subject]
    else:
        return f"Applciation information not found at {config_file_location}"


def get_application_config_subject_item(subject: str, item: str) -> str:
    """ Get information about a subject item of the config file """
    if os.path.exists(config_file_location):
        with open(config_file_location) as cfg:
            config = json.load(cfg)
        return config[subject][item]
    else:
        return f"Applciation information not found at {config_file_location}"


def change_config(subject: str, item: str, value: str):
    """ Change value of item in the config file. Subject, Item and Value must be given"""
    if os.path.exists(config_file_location):
        with open(config_file_location) as cfg:
            config = json.load(cfg)
        try:
            config[subject][item] = value
            with open(config_file_location, 'w') as cfg:
                json.dump(config, cfg, indent=2)
            return f"Config file succesfully changed {config[subject][item]}"
        except KeyError:
            return f"Object \"{subject}:{item}\" not found"
    else:
        return f"Applciation information not found at {config_file_location}"

