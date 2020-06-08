.. Windows Deployment Tool documentation master file, created by
   sphinx-quickstart on Mon Jun  8 16:32:15 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Windows Deployment Tool documentatie
====================================

Welkom op de Windows Deployment Tool documentatie pagina!
Hier vindt je alle details over de mogelijkheden en instellingen van de Windows Deployment Tool.

.. _hoofdfuncties-index:

Hoofdfuncties
-------------

.. toctree::
   :maxdepth: 1

   veiligheid
   windows_firewall
   computernaam_aanpassen
   windows_instellingen
   energieplan_aanpassen

.. _modules-index:

Modules
-------

.. toctree::
   :maxdepth: 1

   windows_gebruikers
   systeeminformatie
   administrator_account

.. _workflow-index:

Workflow
--------
De ideale workflow voor de Windows Deployment Tool is als volgt:

* Doorloop alle **Hoofdfuncties**
* Voeg :doc:`Windows gebruikers <windows_gebruikers>` toe
* Installeer updates :doc:`(Systeeminformatie en Rapportage) <systeeminformatie>`
* Herstart de Pc
* Voer een systeemcontrole uit :doc:`(Systeeminformatie en Rapportage) <systeeminformatie>`
* Maak de rapportage
* De rapportage moet opgeslagen worden in de projecten folder

.. _download-install-index:

Downloaden, installeren en updaten
----------------------------------
De Windows Deployment Tool kan via de koppeling gedownload worden. `Download`_

Doorloop de stappen van de installatie en start de Windows Deployment Tool.

Wanneer er een nieuwe versie beschikbaar is zal er een melding worden weergegeven in de applicatie.
Ook kan via het **Help** menu in de menubalk gecontroleerd worden op updates door de knop **Controleer op updates**
te gebruiken. Deze controles werken alleen als de Pc is verbonden met het internet.
Wanneer er geen internetverbinding beschikbaar is zal de nieuwe versie gedownload moeten worden
via bovenstaande koppeling.

.. _logging-index:

Logging
-------
Bij het uitvoeren van functies en controles worden de uitkomsten en mogelijke errors weggeschreven in een
logbestand op de Pc. De log is te openen via het **Help** menu in de menubalk, klik vervolgens op **WDT Logging**.

De log kan bekeken, geleegd, geëxporteerd en verwijderd worden via het venster van WDT logging.

.. _licentie-index:

Licentie
--------
De Windows Deployment Tool is uitgegeven onder `GNU General Public License`_

.. _laatste-info-index:

Laatste info
------------
Bedankt voor het gebruik van de Windows Deployment Tool, blijf op de hoogte van alle nieuwe mogelijkheden in toekomstige updates.
Eventuele bugs, verbeteringen en suggesties voor Windows Deployment Tool kun je plaatsen in de `Issue Tracker`_
Bij bugs graag de WDT log toevoegen aan de melding.

.. image:: https://img.shields.io/github/v/release/jebr/windows-deployment-tool?label=Release
.. image:: https://img.shields.io/github/release-date/jebr/windows-deployment-tool?color=orange&label=Release%20date
.. image:: https://img.shields.io/github/downloads/jebr/windows-deployment-tool/total?color=green&label=Downloads



.. _`Download`: https://github.com/jebr/windows-deployment-tool/releases
.. _`GNU General Public License`: https://raw.githubusercontent.com/jebr/windows-deployment-tool/master/LICENSE
.. _`Issue Tracker`: https://github.com/jebr/windows-deployment-tool/issues


.. Indices and tables
.. ==================

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
