Windows Firewall
================

De Windows Firewall functionaliteit biedt de mogelijkheid om uitzonderingen te maken in de firewall. Standaard worden de uitzonderingen toegepast op alle profielen (Domein, Privé, Openbaar).

ICMP
----
Deze functie zorgt ervoor dat er een uitzondering in de firewall wordt gemaakt zodat het mogelijk is om de Pc te benaderen via het ICMP protocol. `Uitleg over ICMP (Wikipedia)`_

Discovery
---------
Deze functie zorgt ervoor dat er een uitzondering in de firewall wordt gemaakt zodat de Pc gevonden kan worden in het netwerk. Bij elke nieuwe netwerkverbinding zal Windows vragen of de Pc zichtbaar moet zijn in het netwerk. Wanneer er op **nee** wordt geklikt zal de Pc niet zichtbaar zijn en is het vaak niet mogelijk om een verbinding, met een applicatie op de Pc op te bouwen. Het kan dus zijn dat deze functie op een later moment nog een keer uitgevoerd moet worden.


Technische beschrijving firewall instellingen
---------------------------------------------
Firewall instellingen zijn taalafhankelijk. Dit betekend dat de Windows Deployment Tool zal proberen om de instellingen uit te voeren in het Nederlands. Wanneer dit niet lukt zal de Engelse taal gebruikt worden, wat werkt in de meeste gevallen ook als de taal anders is ingesteld dan Engels.

**ICMP**

::

    Set-NetFirewallRule -DisplayName \"Bestands- en printerdeling (Echoaanvraag- ICMPv4-In)\" -Profile Any -Enabled True'

**Discovery**

::

    netsh advfirewall firewall set rule group=”Network Discovery” new enable=Yes'


.. _`Uitleg over ICMP (Wikipedia)`: https://nl.wikipedia.org/wiki/Internet_Control_Message_Protocol