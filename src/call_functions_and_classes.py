from classes.productkey.windows_productkey import WindowsProductKey
from classes.basics.base_functions import BaseFunctions
from classes.system.system_information import HardWareInformation
from classes.system.system_information import WindowsInformation
from classes.system.system_checks import SystemChecks

powershell = BaseFunctions.powershell

print("==== TEST SYSTEM CHECKS IMPORT")
print(SystemChecks.windows7_check())
print(SystemChecks.windows_version_check())

print("==== TEST WINDOWS PRODUCT KEY IMPORT ====")
extract_key = WindowsProductKey.write_product_key_to_file()
print(extract_key)
key = WindowsProductKey.extract_product_key()
print(key)

# delete_key_file = WindowsProductKey.remove_product_key_json()
# print(delete_key_file)

print("==== TEST WINDOWS INFO IMPORT ====")
print(WindowsInformation.windows_release_build())

print("==== TEST HARDWARE INFO IMPORT ====")
print(HardWareInformation.pc_type())

print("==== TEST BASE FUNCTIONS ====")
print("Clipboard information")
print(powershell(['Get-Clipboard']))



# wp = classes.WindowsProductkey()
# print(wp.write_product_key_to_file())
#
# print(wp.extract_product_key())

# wi = WindowsInformation
# print(wi.WindowsInformation.windows_operating_system)
#
# wi = WindowsInformation.windows_language()
# print(wi)





