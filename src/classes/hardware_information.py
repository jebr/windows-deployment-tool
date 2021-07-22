
# from .base_functions import powershell
import base_functions as bf
import windows_information as wi


class HardWareInformation:
    """Gather hardware information of the Pc"""

    def __init__(self):
        windows_os = wi.WindowsInformation.windows_operating_system
        powershell = bf.BaseFunctions.powershell
        print(self.pc_manufacturer)


    @staticmethod
    def pc_manufacturer() -> str:
        """Returns the manufacturer of the Pc"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).manufacturer"
        manufacturer = powershell([syntax])
        return manufacturer.rstrip()

    @staticmethod
    def pc_model(self) -> str:
        """Return de model of the Pc's manufacturer"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).model"
        model = self.powershell([syntax])
        return model.rstrip()

    @staticmethod
    def pc_type(self) -> str:
        """Returns Pc type like desktop/laptop/server etc."""

        syntax = "(Get-WmiObject Win32_ComputerSystem).PCSystemTypeEx"
        if "7" in self.windows_os:
            pc_type = "Desktop"
        else:
            type_number = self.powershell([syntax])
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
    def pc_ram(self) -> str:
        """Returns RAM value in GB"""
        syntax = "(Get-WmiObject Win32_ComputerSystem).totalphysicalmemory"
        bytes_number = self.powershell([syntax])
        bytes_number = int(bytes_number)
        gb_number = bytes_number / (1024 ** 3)
        gb_number = round(gb_number)
        return f"{gb_number} GB"

    @staticmethod
    def pc_processor(self) -> str:
        """Returns Processor type"""
        syntax = "(Get-WmiObject Win32_Processor).name"
        processor_name = self.powershell([syntax])
        return processor_name.rstrip()

    @staticmethod
    def pc_processor_cores(self) -> str:
        """Returns number of cores"""
        syntax = "(Get-WmiObject Win32_Processor).NumberOfCores"
        processor_cores = self.powershell([syntax])
        return processor_cores.rstrip()

    @staticmethod
    def pc_processor_logical_processors(self) -> str:
        """Returns number of logical processors"""
        syntax = "(Get-WmiObject Win32_Processor).NumberOfLogicalProcessors"
        processor_logical_processors = self.powershell([syntax])
        return processor_logical_processors.rstrip()

    @staticmethod
    def pc_bios_version(self) -> str:
        """Returns BIOS version"""
        syntax = "(Get-WmiObject -class Win32_Bios).SMBIOSBIOSVersion"
        bios_version = self.powershell([syntax])
        return bios_version.rstrip()

    @staticmethod
    def pc_servicetag(self) -> str:
        """Returns servicetag of manufacturer"""
        syntax = "(Get-WmiObject -class Win32_Bios).serialnumber"
        serialnumber = self.powershell([syntax])
        return serialnumber.rstrip()

hi = HardWareInformation()
print(hi.pc_manufacturer())