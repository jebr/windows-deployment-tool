Windows Instellingen
====================

De volgende Windows instellingen kunnen uitgevoerd worden via de Windows Deployment Tool.

Remote Desktop Activeren
------------------------

Wanneer Remote Desktop wordt geactiveerd is het mogelijk om de Pc op afstand volledig over te nemen.
`Uitleg over Remote Desktop (Wikipedia)`_

Support informatie toevoegen
----------------------------

Met het toevoegen van de Support informatie worden de volgende onderdelen ingevuld in het systeemoverzicht:
 - Manufacturer: Heijmans Utiliteit Safety & Security
 - Model: Leverancier Pc en Type
 - SupportHours: 24/7
 - SupportPhone: +31 (0) 88 443 50 03
 - SupportURL: https://www.heijmans.nl
 - Logo: Heijmans logo

Verder wordt de servicetag van de Pc of Server toegevoegd aan de beschrijving van de Pc of Server. De servicetag
wordt gebruikt als basis voor het contract met de leverancier.


Technische beschrijving RDP
---------------------------

Om RDP mogelijk te maken worden de volgende firewall instellingen toegepast.

::

   Extern bureaublad - Gebruikersmodus (TCP-In) Enabled
   Extern bureaublad - Gebruikersmodus (UDP-In) Enabled
   Extern bureaublad - Schaduw (TCP-In) Enabled

De volgende register aanpassingen zijn nodig om RDP mogelijk te maken.

::

   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections 0
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\\SecurityLayer 0
   HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\\RDP-Tcp\\UserAuthentication 0

.. _`Uitleg over Remote Desktop (Wikipedia)`: https://nl.wikipedia.org/wiki/Remote_desktop


Technische beschrijving Support (OEM) informatie
------------------------------------------------

De volgende register aanpassingen worden gemaakt om de informatie weer te geven

::

    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\Manufacturer
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\Logo
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\Model
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\SupportHours
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\SupportPhone
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation\SupportURL