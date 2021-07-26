

# from classes.basics.base_functions import BaseFunctions
from classes.productkey.windows_productkey import WindowsProductKey
from classes.basics.base_functions import BaseFunctions
from classes.system.system_information import HardWareInformation

powershell = BaseFunctions.powershell

extract_key = WindowsProductKey.write_product_key_to_file()
print(extract_key)
key = WindowsProductKey.extract_product_key()
print(key)

# delete_key_file = WindowsProductKey.remove_product_key_json()
# print(delete_key_file)

print(HardWareInformation.pc_type())

# wp = classes.WindowsProductkey()
# print(wp.write_product_key_to_file())
#
# print(wp.extract_product_key())

# wi = WindowsInformation
# print(wi.WindowsInformation.windows_operating_system)
#
# wi = WindowsInformation.windows_language()
# print(wi)

# print(powershell(['hostname']))



