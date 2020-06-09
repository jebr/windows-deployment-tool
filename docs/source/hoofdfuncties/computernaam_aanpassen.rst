Computernaam aanpassen
======================

Criteria Computernaam
---------------------

De computernaam (hostname) van de computer moet aangepast worden voordat hij in productie wordt geplaatst.
Het is belangrijk om een duidelijke naam te kiezen die beschrijft waar de Pc voor bedoeld is.
De naam van de Pc moet aan de volgende voorwaarden voldoen:

* De computernaam mag niet langer zijn dan 15 karakters
* De computernaam mag niet korter zijn dan 3 karakters
* De computernaam mag niet beginnen en eindigen met een **-**
* De volgende karakters zijn toegestaan voor de computernaam
   * **abcdefghijklmnopqrstuvwxyz**
   * **ABCDEFGHIJKLMNOPQRSTUVWXYZ**
   * **-**

De huidige computernaam is zichtbaar in de applicatie op de de hoofdpagina onder **Computernaam**.
Ook is de computernaam op te vragen via de tab **Systeeminformatie**

Voor het toepassen van de computernaam is het noodzakelijk dat de Pc herstart wordt.
Het beste is om heel de Windows Deployment Tool te doorlopen en vervolgens de computer te herstarten
om alle instellingen toe te passen.


Technische beschrijving aanpassen computernaam
----------------------------------------------
Windows Deployment Tool controleert de ingevoerde computernaam op bovenstaande voorwaarden,
als hier niet aan wordt voldaan zal er een melding worden weergegeven.

Voor het wijzigen van de computernaam wordt onderstaande syntax gebruikt:

::

    Rename-Computer -NewName {nieuwe computernaam}