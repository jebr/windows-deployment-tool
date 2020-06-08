Windows Instellingen
====================

.. contents::

De volgende Windows instellingen kunnen uitgevoerd worden via de Windows Deployment Tool.

Remote Desktop Activeren
------------------------

Wanneer Remote Desktop wordt geactiveerd is het mogelijk om de Pc op afstand volledig over te nemen.
`Uitleg over Remote Desktop (Wikipedia)`_


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

