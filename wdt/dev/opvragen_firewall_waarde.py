# Opvragen firewall waarde met Python

import os
import subprocess

rule = str('Get-NetFirewallRule -DisplayName \"Extern bureaublad - Gebruikersmodus (TCP-In)\"')

check = 'Get-NetFirewallRule -Action Allow -Enabled False -Direction Inbound -DisplayGroup \"Extern bureau*\" | select DisplayName, DisplayGroup, Enabled'

try:
	output = str(subprocess.check_output(['powershell.exe', check]))
	if "False" in output:
		print("De poorten worden geblokkeerd")
except CalledProcessError:
	print("De poorten zijn vrijgegeven")

print(output)
print(type(output))

