.. Windows Deployment Tool documentation master file, created by Jeroen Brauns
   sphinx-quickstart on Mon Jun  8 16:32:15 2020.

==============================================
Windows Deployment Tool v2.41 documentatie
==============================================

Welkom op de Windows Deployment Tool documentatie pagina!
Hier vindt je alle details over de mogelijkheden en instellingen van de Windows Deployment Tool.

.. _hoofdfuncties-index:

Hoofdfuncties
=============

* :doc:`hoofdfuncties/veiligheid`
* :doc:`hoofdfuncties/windows_firewall`
* :doc:`hoofdfuncties/computernaam_aanpassen`
* :doc:`hoofdfuncties/windows_instellingen`
* :doc:`hoofdfuncties/energieplan_aanpassen`

.. toctree::
   :maxdepth: 1
   :caption: Hoofdfuncties
   :hidden:

   hoofdfuncties/veiligheid
   hoofdfuncties/windows_firewall
   hoofdfuncties/computernaam_aanpassen
   hoofdfuncties/windows_instellingen
   hoofdfuncties/energieplan_aanpassen


.. _modules-index:

Modules
=======

* :doc:`modules/windows_gebruikers`
* :doc:`modules/systeeminformatie`
* :doc:`modules/administrator_account`

.. toctree::
   :maxdepth: 1
   :caption: Modules
   :hidden:

   modules/windows_gebruikers
   modules/systeeminformatie
   modules/administrator_account

.. _workflow-index:

Workflow
========

De ideale workflow voor de Windows Deployment Tool is als volgt:

* Doorloop alle :ref:`hoofdfuncties-index`
* Voeg :doc:`Windows gebruikers <modules/windows_gebruikers>` toe
* Installeer updates :doc:`(Systeeminformatie en Rapportage) <modules/systeeminformatie>`
* Herstart de Pc
* Voer een systeemcontrole uit :doc:`(Systeeminformatie en Rapportage) <modules/systeeminformatie>`
* Maak de rapportage
* De rapportage moet opgeslagen worden in de projecten folder

.. _download-install-index:

Downloaden, installeren en updaten
==================================
De Windows Deployment Tool kan via onderstaande koppeling gedwonload worden.

Download: `Windows Deployment Tool`_

Doorloop de stappen van de installatie en start de Windows Deployment Tool.

Wanneer er een nieuwe versie beschikbaar is zal er een melding worden weergegeven in de applicatie.
Ook kan via het menu **Info** -> **Controleer op updates** gecontroleerd worden op updates.
De update controle werkt alleen als de Pc/Server is verbonden met het internet.
Wanneer er geen internetverbinding beschikbaar is kan een nieuwe versie gedownload worden via bovenstaande koppeling.

.. _logging-index:

Logging
=======
Bij het uitvoeren van functies en controles worden de uitkomsten en mogelijke errors weggeschreven in een
logbestand op de Pc. De log is te openen via het **Help** menu in de menubalk, klik vervolgens op **WDT Logging**.

De log kan bekeken, geleegd, geëxporteerd en verwijderd worden via het venster van WDT logging.

.. _licentie-index:

Licentie
========
De Windows Deployment Tool is uitgegeven onder `GNU General Public License`_

.. _laatste-info-index:

Aanvullende gegevens
====================

.. toctree::
   :maxdepth: 2
   :caption: Aanvullende gegevens
   :hidden:

   aanvullende-gegevens/release_notes


* :doc:`aanvullende-gegevens/release_notes`

Laatste info
============
Bedankt voor het gebruik van de Windows Deployment Tool, blijf op de hoogte van alle nieuwe mogelijkheden in toekomstige updates.
Eventuele bugs, verbeteringen en suggesties voor Windows Deployment Tool kun je plaatsen in de `Issue Tracker`_
Bij bugs graag de WDT log toevoegen aan de melding.

.. image:: https://img.shields.io/github/v/release/jebr/windows-deployment-tool?label=Release
.. image:: https://img.shields.io/github/release-date/jebr/windows-deployment-tool?color=orange&label=Release%20date
.. image:: https://img.shields.io/github/downloads/jebr/windows-deployment-tool/total?color=green&label=Downloads


.. _`Windows Deployment Tool`: https://github.com/jebr/windows-deployment-tool/releases
.. _`GNU General Public License`: https://raw.githubusercontent.com/jebr/windows-deployment-tool/master/LICENSE
.. _`Issue Tracker`: https://github.com/jebr/windows-deployment-tool/issues


.. Indices and tables
.. ==================

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
