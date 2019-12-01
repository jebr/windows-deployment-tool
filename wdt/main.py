import platform  # To get current platform, use platform.platform()
import sys
import csv
import os
import locale  # Controleren van de OS taal
import ctypes  # Controleren OS taal

from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui

try:
    os.chdir(os.path.dirname(sys.argv[0]))
except Exception:
    pass

from cmd_based_functions import *


def isUserAdmin():

    if os.name == 'nt':
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            traceback.print_exc()
            print("Admin check failed, assuming not an admin.")
            return False
    elif os.name == 'posix':
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise RuntimeError('Os not supported')


class MainPage(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('./ui_files/main_window.ui'), self)
        self.setFixedSize(900, 700)
        self.setWindowIcon(QtGui.QIcon(resource_path('./data/wdt.ico')))
        self.actionAbout.triggered.connect(self.open_about_popup)
        self.actionLicence.triggered.connect(self.open_licence_popup)
        self.actionSettings.triggered.connect(self.open_settings_popup)
        self.pushButton_info_hostname.clicked.connect(self.open_hostname_help)
        self.pushButton_import_csv.clicked.connect(self.load_csv_file)
        self.tableWidget_add_users.resizeRowsToContents()

        # Gebruikers toevoegen
        self.pushButton_users_clear.clicked.connect(self.clear_users)
        # Tabel leegmaken

        # Hostname
        self.label_hostname.setText('Huidige computernaam: {}'.format(os.getenv('COMPUTERNAME')))
        self.pushButton_set_hostname.clicked.connect(self.set_hostname)

        # USB-storage
        self.pushButton_usb_enable.clicked.connect(self.enable_usb)
        self.pushButton_usb_disable.clicked.connect(self.disable_usb)

        # Firewall instellingen
        self.pushButton_firewall_ping.clicked.connect(self.firewall_ping)

        # Remote desktop (RDP)
        self.pushButton_rdp_enable.clicked.connect(self.enable_rdp)

        # Controleer systeemtaal
        windll = ctypes.windll.kernel32
        windll.GetUserDefaultUILanguage()
        self.os_language = locale.windows_locale[windll.GetUserDefaultUILanguage()]

        # Controleer windows versie
        self.os_version = platform.platform()

        # Systeeminformatie
        self.label_os_language.setText(self.os_language)
        self.label_os_version.setText(self.os_version)

        # Controleer USB activering
        self.usb_check()

    def firewall_ping(self):
        if "nl" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe',
                    'Set-NetFirewallRule -DisplayName \"Bestands- en printerdeling (Echoaanvraag - ICMPv4-In)\" -Profile Any -Enabled True'])
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instelling is niet uitgevoerd!')
            self.infobox('Ping (SMTP) is geactiveerd')
        elif "en" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"File and Printer Sharing (Echo Request - ICMPv4-In)\" -Profile Any -Enabled True'])
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instelling is niet uitgevoerd!')
            self.infobox('Ping (SMTP) is geactiveerd')

    # Functie voor het controleren van de Windows versie
    def os_check(self):
        if "Windows-7" in self.os_version:
            self.warningbox('Windows 7 wordt niet meer ondersteund')
            sys.exit()


    # Functie voor het contoleren van de USB activering
    def usb_check(self):
        self.usb_register_path = "Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
        self.usb_reg_dword = "Start"
        # Controleer de waarde van het register
        self.check_usb = str(subprocess.check_output(['powershell.exe', 'Get-ItemProperty -Path {} -Name {}'.format(self.usb_register_path, self.usb_reg_dword)]))
        # Als de waarde 3 is de USB geactiveerd
        if "3" in self.check_usb:
            self.pushButton_usb_enable.setDisabled(True)
            self.pushButton_usb_disable.setDisabled(False)
        # Als de waarde 4 is de USB gedeactiveerd
        elif "4" in self.check_usb:
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
        else:
            return

    # Functie voor het wijzigen van de computernaam
    def set_hostname(self):
        new_hostname = self.lineEdit_hostname.text()
        if not checkout_hostname(new_hostname):
            self.add_text_to_log('{} is geen geldige computernaam'.format(new_hostname))
            self.criticalbox('Ongeldige computernaam, zie infobox')
            return
        try:
            subprocess.check_call(['powershell.exe', "Rename-Computer -NewName {}".format(new_hostname)])
            self.add_text_to_log('Computernaam is aangepast naar {}'.format(new_hostname))
            self.infobox('De computernaam is aangepast naar: {}'.format(self.lineEdit_hostname.text()))
        except Exception as e:
            self.add_text_to_log(str(e))
        except subprocess.CalledProcessError:
            self.criticalbox('De uitvoering is mislukt!')

    def enable_usb(self):
        try:
            register = 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f'
            subprocess.check_call(register.split(" "))
            self.infobox('USB-opslagapparaten zijn geactiveerd')
            self.usb_check()
        except subprocess.CalledProcessError:
            self.criticalbox('De uitvoering is mislukt! \n\n Is het programma uitgevoerd als Administrator?')

    def disable_usb(self):
        try:
            register = 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f'
            subprocess.check_call(register.split(" "))
            self.infobox('USB-opslagapparaten zijn gedeactiveerd')
            self.usb_check()
        except subprocess.CalledProcessError:
            self.criticalbox('De uitvoering is mislukt! \n\n Is het programma uitgevoerd als Administrator?')

    # Functie voor het activeren van remote desktop
    def enable_rdp(self):
        if "Windows-7" in self.os_version:
            self.infobox('Windows 7 wordt niet langer ondersteund. \n \n Neem contact op met de ontwikkelaar, helpdeskbeveiliging@heijmans.nl')
        else:
            if "nl" in self.os_language:
                try:
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - Gebruikersmodus (TCP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - Gebruikersmodus (UDP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - Schaduw (TCP-In)\" -Profile Any -Enabled True'])
                    # self.infobox('De firewall instellingen zijn geactiveerd')
                except subprocess.CalledProcessError:
                    self.criticalbox('De firewall instellingen zijn niet uitgevoerd')
            elif "en" in self.os_language:
                try:
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - User Mode (TCP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - User Mode (UDP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - Shadow (TCP-In)\" -Profile Any -Enabled True'])
                    # self.infobox('De firewall instellingen zijn geactiveerd')
                except subprocess.CalledProcessError:
                    self.criticalbox('De firewall instellingen zijn niet uitgevoerd')
            try:
                register = [
                'reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f',
                'reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v SecurityLayer /t REG_DWORD /d 0 /f',
                'reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 0 /f']
                # for settings in register:
                #     try:
                #         subprocess.check_call(settings.split(' '))
                #     except subprocess.CalledProcessError:
            except subprocess.CalledProcessError:
                self.criticalbox('De register instellingen zijn mislukt!')
            self.infobox('Remote desktop is geactiveerd')

    def add_text_to_log(self, text):
        '''Adds text to the log tab. Make sure to end each line with a \n
        '''
        self.textBrowser_log.append(text)
        desktop_loc = os.environ['USERPROFILE'] + '\\Desktop'
        os.path.isdir(desktop_loc)
        with open(desktop_loc + 'wtdlog.txt', 'w') as file:
            file.write(self.textBrowser_log.toPlainText())

    # Messageboxen
    def infobox(self, message):
        buttonReply = QMessageBox.information(self, 'Info', message, QMessageBox.Ok)

    def warningbox(self, message):
        buttonReply = QMessageBox.warning(self, 'Warning', message, QMessageBox.Close)

    def criticalbox(self, message):
        buttonReply = QMessageBox.critical(self, 'Error', message, QMessageBox.Close)

    def question(self, message):
        buttonReply = QMessageBox.question(self, 'Question', message, QMessageBox.Ok)

    def noicon(self, message):
        buttonReply = QMessageBox.noicon(self, '', message, QMessageBox.Ok)

    def load_csv_file(self):
        fileName, _ = QFileDialog.getOpenFileName(self,
            "selecteer cvs bestand", "", "csv (*.csv)")
        if not fileName:
            # If window is clicked away
            return
        # Hier moet nog een error afhandeling komen
        # (IndexError: list index out of range)
        # Probeer eens de extentie van een python bestand naar csv te
        # zetten en deze vervolgens te uploaden :D
        with open(fileName) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            # Get the first non empty row number
            for i in range(20):
                if not self.tableWidget_add_users.item(i, 0):
                    break
            # Append the data from cvs to the table
            try:
                for row in readCSV:
                    for j in range(5):
                        self.tableWidget_add_users.setItem(i,
                            j,
                            QTableWidgetItem(row[j]))
                    i += 1
                self.add_text_to_log('Informatie toegevoegd aan tabel van')
                self.add_text_to_log(fileName + '\n')
            except Exception as e:
                self.add_text_to_log('Niet mogelijk om het volgende bestand uit te lezen:')
                self.add_text_to_log(fileName)
                self.add_text_to_log(str(e) + '\n')
                self.warningbox('Let op, bestand niet geimporteerd')

    def clear_users(self):
        self.tableWidget_add_users.clearContents()
        # self.tableWidget_add_users.setRowCount(10)

    def open_about_popup(self):
        AboutPopup_ = AboutPopup()
        AboutPopup_.exec_()

    def open_licence_popup(self):
        LicencePopup_ = LicencePopup()
        LicencePopup_.exec_()

    def open_settings_popup(self):
        SettingsPopup_ = SettingsPopup()
        SettingsPopup_.exec_()

    def open_hostname_help(self):
        HostnamePopup_ = HostnamePopup()
        HostnamePopup_.exec_()



class AboutPopup(QDialog):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('./ui_files/about_popup.r'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('./data/wdt.ico')))


class LicencePopup(QDialog):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('./ui_files/licence_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('./data/wdt.ico')))


class SettingsPopup(QDialog):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('./ui_files/settings_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('./data/wdt.ico')))


class HostnamePopup(QDialog):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('./ui_files/hostname_help_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('./data/wdt.ico')))


def main():
    if not isUserAdmin():
        # Messagebox Uitvoeren als Administrator
        sys.exit(0)

    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())
    os_check()


if __name__ == '__main__':
    main()
