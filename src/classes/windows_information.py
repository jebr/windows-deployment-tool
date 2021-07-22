
# from base_functions import powershell
import base_functions as bf


class WindowsInformation:
    """Gather Windows information"""

    def __init__(self):
        self.powershell = bf.BaseFunctions.powershell

    # @staticmethod
    def windows_operating_system(self) -> str:
        """Returns Windows Operating System Version"""
        syntax = "(Get-WmiObject Win32_OperatingSystem).Caption"
        os = self.powershell([syntax])
        return os.rstrip()


    @staticmethod
    def windows_language(self) -> str:
        """Returns system language"""
        syntax = "(Get-Culture).DisplayName"
        os_language = self.powershell([syntax])
        return os_language.rstrip()

    @staticmethod
    def domain_or_workgroup(self) -> str:
        """Returns whether the Pc is in a workgroup or a domain"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).domain"
        domain_workgroup = self.powershell([syntax])
        return domain_workgroup.rstrip()

    @staticmethod
    def computername(self) -> str:
        """Returns the hostname/computername of the Pc"""
        syntax = "(Get-WMIObject Win32_ComputerSystem).name"
        hostname = self.powershell([syntax])
        return hostname.rstrip()

    @staticmethod
    def windows_release_build(self) -> str:
        """Returns Windows Build Number"""
        syntax = "(Get-ItemProperty " \
                 "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion')." \
                 "ReleaseID"
        w_release_build = self.powershell([syntax])
        return w_release_build.rstrip()

    @staticmethod
    def windows_release_version(self) -> str:
        """Returns Windows release version number"""
        syntax = "(Get-WmiObject Win32_OperatingSystem).Version"
        w_release_version = self.powershell([syntax])
        return w_release_version.rstrip()
