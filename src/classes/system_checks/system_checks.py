from ..basics.base_functions import powershell
import platform
import os
from ..system.system_information import WindowsInformation


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

    @staticmethod
    def ntp_client_check() -> str:
        """ Returns domain or IP-address from the NTP set server  """
        ntp_register_path = 'Registry::"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\w32time\\Parameters"'
        ntp_reg_sz = "NtpServer"
        ntp_server_address = \
            powershell([f'Get-ItemPropertyValue -Path {ntp_register_path} -Name {ntp_reg_sz}']).strip()
        if "0" in ntp_server_address:
            return ntp_server_address.rstrip(",x0123456789")

    @staticmethod
    def ntp_server_check() -> bool:
        """ Returns  """
        ntp_register_path = 'Registry::"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\w32time\\TimeProviders\\NtpServer"'
        ntp_reg_sz = "Enabled"
        ntp_server_enabled = powershell([f'Get-ItemPropertyValue -Path {ntp_register_path} -Name {ntp_reg_sz}']).strip()
        if ntp_server_enabled == '1':
            return True
        else:
            return False

    @staticmethod
    def wf_discovery_check() -> bool:
        # Netwerk detecteren (NB-Datagram-In)
        # Network Discovery (NB-Datagram-In)
        if "nl" in WindowsInformation.windows_language():
            check_nl = powershell(['Get-NetFirewallRule -DisplayName "Netwerk detecteren (NB-Datagram-In)" '
                                        '| select DisplayName, Enabled'])
            check_true = check_nl.count("True")
            if check_true == 3:
                return True
            else:
                return False
        else:
            check_en = powershell(['Get-NetFirewallRule -DisplayName "Network Discovery (NB-Datagram-In)" '
                                        '| select DisplayName, Enabled'])
            check_true = check_en.count("True")
            if check_true == 3:
                return True
            else:
                return False

    @staticmethod
    def wf_icmp_check() -> bool:
        icmp_rule_nl = str('Get-NetFirewallRule -DisplayName \"Bestands- en printerdeling '
                           '(Echoaanvraag - ICMPv4-In)\" | select DisplayName, Enabled')
        icmp_rule_en = str('Get-NetFirewallRule -DisplayName \"File and Printer Sharing '
                           '(Echo Request - ICMPv4-In)\" | select DisplayName, Enabled')
        if "nl" in WindowsInformation.windows_language():
            check_nl = powershell([icmp_rule_nl])
            # check_nl = str(subprocess.check_output(['powershell.exe', icmp_rule_nl]))
            if "True" in check_nl:
                return True
            else:
                return False
        else:
            check_en = powershell([icmp_rule_en])
            # check_en = str(subprocess.check_output(['powershell.exe', icmp_rule_en]))
            if "True" in check_en:
                return True
            else:
                return False

    @staticmethod
    def admin_user_enabled_check() -> bool:
        """ Check if local Administrator account is enabled """
        local_admin_enabled = powershell(['(Get-LocalUser Administrator).enabled'])
        if eval(local_admin_enabled):
            return True
        else:
            return False

