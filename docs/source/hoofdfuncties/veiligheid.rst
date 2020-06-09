Veiligheid
==========

Security policy
---------------

Met het instellen van de security policy worden den instellingen zoals gewenst geactiveerd. De complete policy is terug te vinden op `GitHub`_.

Bij het toepassen van de nieuwe security policy wordt een back-up gemaakt van de huidige policy en deze wordt gekopieerd naar de desktop. De security policy back-up heeft de bestandsnaam: **backup_secpol.inf**. Maak een back-up van het bestand om op een later moment de originele policy te kunnen herstellen.

Na het toepassen van de security policy zal de lokale policy geüpdatet worden. Voor het toepassen van de security policy moet de gebruiker afgemeld- en aangemeld worden. Het beste is om heel de Windows Deployment Tool te doorlopen en vervolgens de computer te herstarten om alle instellingen toe te passen.

USB-opslagapparaat Activeren / Deactiveren
------------------------------------------

Bij het uitvoeren van de functie **USB-opslagapparaat deactiveren** zal het niet meer mogelijk zijn om USB-sticks of andere, via USB verbonden opslagmedia te gebruiken op de Pc. Het blijft nog wel mogelijk om een toestenbord, muis en andere USB-apparaten aan te sluiten. Wanneer de functie **USB-opslagapparaat activeren** wordt uitgevoerd kunnen USB-opslagmedia weer gebruikt worden.



Technische beschrijving USB-opslagapparaat
------------------------------------------
Voor het blokkeren van USB-opslagmedia wordt de register waarde ``HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\\Start`` op ``4`` gezet.

Wanneer de USB-opslagmedia weer geactiveerd moet worden zal de waarde op ``3`` worden gezet.

.. _`GitHub`: https://github.com/jebr/windows-deployment-tool/blob/master/src/resources/security/secpol_new.inf
