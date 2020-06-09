Lokale Windows gebruikers toevoegen
===================================

Met de Windows Deployment Tool is het mogelijk om lokale Windows gebruikers toe te voegen aan de Pc.
De gebruikers kunnen op 2 manieren toegevoegd worden aan de Pc.

1. Uploaden van een CSV bestand met daarin de gerbuikers
2. Invullen van de tabel in de Windows Deployment Tool.

Een combinatie van deze twee is ook mogelijk. Wanneer een CSV bestand is geüpload naar de Windows Deployment Tool
kunnen daarna nog gebruikers aan de tabel toegevoegd worden. Er kunnen maximaal 20 gebruikers per keer worden toegevoegd.

Criteria Gebruikersnaam
-----------------------
Windows gebruikersnaam moet voldoen aan de volgende voorwaarden:

* De gebruikersnaam mag niet langer zijn dan 20 karakters
* De gebruikersnaam mag niet alleen uit spaties bestaan
* De gebruikersnaam mag niet alleen uit punten bestaan
* De gebruikersnaam mag niet hetzelfde zijn als de computernaam
* De gebruikersnaam mag niet beginnen of eindigen met een spatie
* De volgende karakters zijn niet toegestaan in een gebruikersnaam
* De volgende karakters mogen niet in een gebruikersnaam gebruikt worden

   * **" / \ [ ] : ; | = , + * ? < > @**

Criteria Wachtwoord
-------------------

* De gebruikersnaam mag niet voorkomen in het wachtwoord
* De volledige naam mag niet voorkomen in het wachtwoord
* Het wachtwoord moet tenminste 8 karakters lang zijn
* Het wachtwoord moet tekens bevatten uit de vier onderstaande categorieën

   * **abcdefghijklmnopqrstuvwxyz**
   * **ABCDEFGHIJKLMNOPQRSTUVWXYZ**
   * **1234567890**
   * **~!@#$%^&*_-+=`|\(){}[]:;"`',.?/**

Uitleg invulvelden
------------------
Alle velden zijn **verplicht** om in te vullen. Wanneer **Ja** wordt ingevuld in het veld **Administrator**
zal de gebruiker worden toegevoegd aan de groep **Windows Administrators**. Wanneer er **Nee** wordt ingevuld
in het veld **Administrator** zal de gebruiker aan de **Windows Users** groep worden toegevoegd.

Vul in het veld beschrijving een duidelijke omschrijving in van het account.

Import CSV
----------
Kolommen die gebruikt moeten worden in de CSV voor het toevoegen van de lokale Windows gebruikers zijn:
*gebruikersnaam,wachtwoord,volledige naam,beschrijving,ja/nee*

**Bijvoorbeeld:**

+----------------+------------+----------------+----------------------+---------------+
| Gebruikersnaam | Wachtwoord | Volledige naam | Beschrijving         | Administrator |
+================+============+================+======================+===============+
| jugio          | WJ0oG-@oj8 | Gio Jules      | Applicatie gebruiker | Nee           |
+----------------+------------+----------------+----------------------+---------------+

Knoppen
-------
**Import CSV** - Importeer gebruikers middels een CSV bestand wat voldoet aan de bovenstaande beschrijving.

**Tabel leegmaken** - Alle data wordt uit de tabel verwijderd. Huidige Windows gebruikers zullen niet verwijderd worden.

**Gebruikers toevoegen** - gebruikers die in de tabel staan worden toegevoegd aan Windows.
Na het toevoegen zal de tabel automatisch leeggemaakt worden.

.. image:: /images/WDT-screenshot-add-users.png

