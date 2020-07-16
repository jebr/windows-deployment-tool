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

NTP Server activeren
----------------------------

Met het activeren van de NTP server wordt de Pc / Server ingesteld als NTP Server voor het netwerk.
Apparaten binnen het netwerk kunnen vervolgens de tijd synchroniseren met de NTP Server. Merk op dat wanneer de NTP
Server wordt geactiveerd ook de NTP Client ingesteld kan worden. Op deze manier fungeert de Pc / Server als NTP Server
binnen het netwerk en wordt de tijd van de server gesynchroniseerd met de tijd van de ingestelde NTP Client gegevens.

NTP Client activeren
----------------------------

Met het activeren van de NTP Client wordt de server ingesteld waarmee de Pc of Server verbinding gaat maken om de
tijd te synchroniseren. Het adres van de NTP Server kan een IP adres zijn of een computernaam.


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


Technische beschrijving NTP server
----------------------------------

De volgende register waarden worden aangepast met het instellen van de NTP Server

::

    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w32time\TimeProviders\NtpServer\Enabled 1
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\W32Time\Config\AnnounceFlags 5
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\W32Time\Config\AnnounceFlags 5

De volgende Firewall instelling wordt ingesteld

::

    dir=in action=allow protocol=UDP localport=123 name="Allow NTP sync"


Technische beschrijving NTP client
----------------------------------

De volgende register waarde wordt aangepast met het instellen van de NTP Client

::

    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\w32time\Parameters\NtpServer server_address,0x8