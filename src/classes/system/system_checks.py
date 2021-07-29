from ..basics.base_functions import BaseFunctions
import platform
import os
powershell = BaseFunctions.powershell


class SystemChecks:
    """" Windows Deployment Tool System Checks"""

    @staticmethod
    def windows7_check() -> bool:
        """ Returns true if OS version is Windows 7 """
        os_version = platform.platform()
        if "Windows-7" in os_version:
            return True
        else:
            return False

    @staticmethod
    def windows_version_check() -> str:
        """ Returns description of Windows version eg. Windows 10 Pro"""
        windows_version = powershell(['(Get-WmiObject -class Win32_OperatingSystem).Caption'])
        windows_version = windows_version.rstrip()
        return windows_version

    @staticmethod
    def energy_check() -> str:
        """ Returns information about energy plan"""
        energy_on_scheme = '00000000-0000-0000-0000-000000000000'
        energy_lock_scheme = '39ff2e23-e11c-4fc3-ab0f-da25fadb8a89'

        active_scheme = powershell(['powercfg /getactivescheme'])

        if energy_on_scheme in active_scheme:
            return "Altijd aan"
        if energy_lock_scheme in active_scheme:
            return "Automatisch vergrendelen"
        else:
            return "Standaard energieplan"

    @staticmethod
    def secpol_check() -> bool:
        """ Returns True if file c:\\windows\\system32\\secpol_new.inf exists"""
        path = 'c:\\windows\\system32\\secpol_new.inf'
        if os.path.exists(path):
            return True
        else:
            return False

    @staticmethod
    def rdp_check() -> bool:
        """ Returns True if registry key HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\
        Terminal Server\\fDenyTSConnections == 0"""
        rdp_register_path = 'Registry::"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"'
        rdp_reg_dword = "fDenyTSConnections"
        check_rdp = powershell([f'Get-ItemProperty -Path {rdp_register_path} -Name {rdp_reg_dword}'])
        if "0" in check_rdp:
            return True
        else:
            return False

    @staticmethod
    def support_info_check():
        # TODO: functie afmaken
        oem_info_path = 'Registry::"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation"'
        oem_reg_sz = "Manufacturer"
        support_info_check = powershell([f'Get-ItemProperty -Path {oem_info_path} -Name {oem_reg_sz}'])


