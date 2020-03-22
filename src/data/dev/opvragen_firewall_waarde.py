# Opvragen firewall waarde met Python

import os
import subprocess

rule = str('Get-NetFirewallRule -DisplayName \"Extern bureaublad - Gebruikersmodus (TCP-In)\"')

check = 'Get-NetFirewallRule -Action Allow -Enabled False -Direction Inbound -DisplayGroup \"Extern bureau*\" | select DisplayName, DisplayGroup, Enabled'

icmp_rule = str('Get-NetFirewallRule -Action Allow -Enabled False -Direction Inbound -Displayname "File and Printer Sharing (Echo Request - ICMPv4-In)" | select DisplayName, DisplayGroup, Enabled')

# icmp_rule_nl = 'Get-NetFirewallRule -Action Allow -Enabled False -Direction Inbound -Displayname \"Bestands- en ' \
# 			   'printerdeling (Echoaanvraag - ICMPv4-In)\" | select DisplayName, DisplayGroup, Enabled'

icmp_rule_nl = 'Get-NetFirewallRule -Action Allow -Enabled True -Direction Inbound | select DisplayName, Enabled'

# Get-NetFirewallRule -Action Allow -Enabled False -Direction Inbound -Displayname "Bestands- en printerdeling (Echoaanvraag - ICMPv4-In)" | select DisplayName, DisplayGroup, Enabled
# print(icmp_rule_nl)
# print(type(icmp_rule_nl))

try:
	output = str(subprocess.check_output(['powershell.exe', icmp_rule_nl]))
	if "Bestands- en printerdeling (Echoaanvraag - ICMPv4-In)" in output:
		print("De poorten zijn vrijgegeven")
	else:
		print("De poorten worden geblokkeerd")
except subprocess.CalledProcessError:
	print('De functie wordt niet uitgevoerd.')

