from ..basics.base_functions import BaseFunctions
powershell = BaseFunctions.powershell


class WindowsInformation:
    """Gather Windows information"""

    @staticmethod
    def windows_operating_system() -> str:
        """Returns Windows Operating System Version"""
        syntax = ["(Get-WmiObject Win32_OperatingSystem).Caption"]
        os = powershell(syntax)
        return os.rstrip()

    @staticmethod
    def windows_language() -> str:
        """Returns system language"""
        syntax = "(Get-Culture).DisplayName"
        os_language = powershell([syntax])
        return os_language.rstrip()

    @staticmethod
    def domain_or_workgroup() -> str:
        """Returns whether the Pc is in a workgroup or a domain"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).domain"
        domain_workgroup = powershell([syntax])
        return domain_workgroup.rstrip()

    @staticmethod
    def computername() -> str:
        """Returns the hostname/computername of the Pc"""
        syntax = "(Get-WMIObject Win32_ComputerSystem).name"
        hostname = powershell([syntax])
        return hostname.rstrip()

    @staticmethod
    def windows_release_build() -> str:
        """Returns Windows Build Number"""
        syntax = "(Get-ItemProperty " \
                 "'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion')." \
                 "ReleaseID"
        w_release_build = powershell([syntax])
        return w_release_build.rstrip()

    @staticmethod
    def windows_release_version() -> str:
        """Returns Windows release version number"""
        syntax = "(Get-WmiObject Win32_OperatingSystem).Version"
        w_release_version = powershell([syntax])
        return w_release_version.rstrip()


class HardWareInformation:
    """Gather hardware information of the Pc"""

    @staticmethod
    def pc_manufacturer() -> str:
        """Returns the manufacturer of the Pc"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).manufacturer"
        manufacturer = powershell([syntax])
        return manufacturer.rstrip()

    @staticmethod
    def pc_model() -> str:
        """Return de model of the Pc's manufacturer"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).model"
        model = powershell([syntax])
        return model.rstrip()

    @staticmethod
    def pc_type() -> str:
        """Returns Pc type like desktop/laptop/server etc."""

        syntax = "(Get-WmiObject Win32_ComputerSystem).PCSystemTypeEx"
        if "7" in WindowsInformation.windows_operating_system():
            pc_type = "Desktop"
        else:
            type_number = powershell([syntax])
            type_number = int(type_number.rstrip())
            if type_number == 1:
                pc_type = "Desktop"
            elif type_number == 2:
                pc_type = "Mobile / Laptop"
            elif type_number == 3:
                pc_type = "Workstation"
            elif type_number == 4:
                pc_type = "Enterprise Server"
            elif type_number == 5:
                pc_type = "Small Office Server (SOHO)"
            elif type_number == 6:
                pc_type = "Appliance PC"
            elif type_number == 7:
                pc_type = "Performance Server"
            elif type_number == 8:
                pc_type = "Maximum"
            else:
                pc_type = "Onbekend product type"

        return pc_type.rstrip()

    @staticmethod
    def pc_ram() -> str:
        """Returns RAM value in GB"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).totalphysicalmemory"
        bytes_number = powershell([syntax])
        bytes_number = int(bytes_number)
        gb_number = bytes_number / (1024 ** 3)
        gb_number = round(gb_number)
        return f"{gb_number} GB"

    @staticmethod
    def pc_processor() -> str:
        """Returns Processor type"""
        syntax = "(Get-WmiObject Win32_Processor).name"
        processor_name = powershell([syntax])
        return processor_name.rstrip()

    @staticmethod
    def pc_processor_cores() -> str:
        """Returns number of cores"""
        syntax = "(Get-WmiObject Win32_Processor).NumberOfCores"
        processor_cores = powershell([syntax])
        return processor_cores.rstrip()

    @staticmethod
    def pc_processor_logical_processors() -> str:
        """Returns number of logical processors"""
        syntax = "(Get-WmiObject Win32_Processor).NumberOfLogicalProcessors"
        processor_logical_processors = powershell([syntax])
        return processor_logical_processors.rstrip()

    @staticmethod
    def pc_bios_version() -> str:
        """Returns BIOS version"""
        syntax = "(Get-WmiObject -class Win32_Bios).SMBIOSBIOSVersion"
        bios_version = powershell([syntax])
        return bios_version.rstrip()

    @staticmethod
    def pc_servicetag() -> str:
        """Returns servicetag of manufacturer"""
        syntax = "(Get-WmiObject -class Win32_Bios).serialnumber"
        serialnumber = powershell([syntax])
        return serialnumber.rstrip()

