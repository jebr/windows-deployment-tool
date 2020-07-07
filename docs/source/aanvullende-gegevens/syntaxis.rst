Syntaxis
========

Op deze pagina zijn een aantal van de gebruikte syntaxis van Windows Deployment tool te vinden.
Wanneer voor functionaliteit Python modules zijn gebruikt zal deze syntaxis hier niet zichtbaar zijn.


Powershell Syntaxis
-------------------

Weergeven van gegevens
~~~~~~~~~~~~~~~~~~~~~~
+---------------+-----------------------------------------------------------------------------------+
| Omschrijving  | Syntax                                                                            |
+===============+===================================================================================+
| Servicetag    | Get-WmiObject -class Win32_Bios).serialnumber                                     |
+---------------+-----------------------------------------------------------------------------------+
| BIOS versie   | Get-WmiObject -class Win32_Bios).serialnumber                                     |
+---------------+-----------------------------------------------------------------------------------+
| Build versie  | (Get-WmiObject Win32_OperatingSystem).Version                                     |
+---------------+-----------------------------------------------------------------------------------+
| Release ID    | (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseID |
+---------------+-----------------------------------------------------------------------------------+
| Release ID    | (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseID |
+---------------+-----------------------------------------------------------------------------------+



CMD Syntaxis
------------

