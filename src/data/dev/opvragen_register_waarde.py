# Opvragen register waarde met Python

import os
import subprocess

path = "Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
name = "Start"

check_usb = str(subprocess.check_output(['powershell.exe', 'Get-ItemProperty -Path {} -Name {}'.format(path, name)]))

print(str(check_usb))
print(type(check_usb))

if "3" in check_usb:
	print("USB geactiveerd")
else:
	print("Error")
