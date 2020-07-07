Syntaxis
========

Op deze pagina zijn een aantal van de gebruikte syntaxis van Windows Deployment tool te vinden.
Wanneer voor functionaliteit Python modules zijn gebruikt zal deze syntaxis hier niet zichtbaar zijn.


Powershell Syntaxis
-------------------

Opvragen van gegevens
~~~~~~~~~~~~~~~~~~~~~~

+------------------------+------------------------------------------------------------------------------------+
| Omschrijving           | Syntax                                                                             |
+========================+====================================================================================+
| Servicetag             | (Get-WmiObject -Class Win32_Bios).serialnumber                                     |
+------------------------+------------------------------------------------------------------------------------+
| BIOS versie            | (Get-WmiObject -Class Win32_Bios).serialnumber                                     |
+------------------------+------------------------------------------------------------------------------------+
| Build versie           | (Get-WmiObject -Class Win32_OperatingSystem).Version                               |
+------------------------+------------------------------------------------------------------------------------+
| Release ID             | (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseID  |
+------------------------+------------------------------------------------------------------------------------+
| Processor              | (Get-WmiObject -Class Win32_Processor).name                                        |
+------------------------+------------------------------------------------------------------------------------+
| CPU Cores              | (Get-WmiObject -Class Win32_Processor).NumberOfCores                               |
+------------------------+------------------------------------------------------------------------------------+
| Logical processors     | (Get-WmiObject -Class Win32_Processor).NumberOfLogicalProcessors                   |
+------------------------+------------------------------------------------------------------------------------+
| Geheugen               | (get-wmiobject -Class Win32_ComputerSystem).totalphysicalmemory                    |
+------------------------+------------------------------------------------------------------------------------+
| PC Soort               | (get-wmiobject -Class Win32_ComputerSystem).PCSystemTypeEx                         |
+------------------------+------------------------------------------------------------------------------------+
| PC Merk                | (get-wmiobject -Class Win32_ComputerSystem).manufacturer                           |
+------------------------+------------------------------------------------------------------------------------+
| PC Model               | (get-wmiobject -Class Win32_ComputerSystem).model                                  |
+------------------------+------------------------------------------------------------------------------------+
| Computernaam           | (get-wmiobject -Class win32_bios).pscomputername                                   |
+------------------------+------------------------------------------------------------------------------------+
| Domein / Werkgroep     | (Get-WmiObject -Class Win32_ComputerSystem).domain                                 |
+------------------------+------------------------------------------------------------------------------------+
| Windows versie         | Get-WmiObject -class Win32_OperatingSystem).Caption                                |
+------------------------+------------------------------------------------------------------------------------+


