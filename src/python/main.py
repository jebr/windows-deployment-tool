import platform  # To get current platform, use platform.platform()
import sys
import csv
import os
import locale  # Controleren van de OS taal
import ctypes  # Controleren OS taal
import subprocess
import getpass
import logging
import shutil

from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui, QtCore


try:
    os.chdir(os.path.dirname(sys.argv[0]))
except Exception:
    pass

# Set logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.disable(logging.DEBUG)


# Resource path bepalen
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.environ.get("_MEIPASS2", os.path.abspath("."))
    # logging.info('Pyinstaller file location {}'.format(base_path))
    return os.path.join(base_path, relative_path)



# Programm uitvoeren als Administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


class MainPage(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('../resources/ui/main_window.ui'), self)
        self.setFixedSize(900, 700)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))
        self.actionAbout.triggered.connect(self.open_about_popup)
        self.actionLicence.triggered.connect(self.open_licence_popup)
        self.actionSettings.triggered.connect(self.open_settings_popup)

        # Hostname
        self.pushButton_info_hostname.clicked.connect(self.open_hostname_help)
        self.pushButton_info_hostname.setIcon(QIcon(QPixmap(resource_path('../icons/circle-info.png'))))
        self.pushButton_info_hostname.setToolTip('Klik voor informatie over computernaam')
        self.label_hostname.setText('Huidige computernaam: {}'.format(os.getenv('COMPUTERNAME')))
        self.pushButton_set_hostname.clicked.connect(self.set_hostname)

        # Import users
        self.pushButton_import_csv.clicked.connect(self.load_csv_file)
        self.tableWidget_add_users.resizeRowsToContents()
        self.pushButton_users_clear.clicked.connect(self.clear_users)

        # Security policy
        self.pushButton_sec_policy.clicked.connect(self.import_sec_policy)

        # USB-storage
        self.pushButton_usb_enable.clicked.connect(self.enable_usb)
        self.pushButton_usb_disable.clicked.connect(self.disable_usb)

        # Firewall instellingen
        self.pushButton_firewall_ping.clicked.connect(self.firewall_ping)
        self.pushButton_firewall_discovery.clicked.connect(self.firewall_network_discovery)

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

    # Functie voor het controleren op Windows 7 versie
    def windows7_check(self):
        if "Windows-7" in self.os_version:
            self.warningbox('Windows 7 wordt niet meer ondersteund')
            sys.exit()

    # Firewall
    def firewall_ping(self):
        if "nl" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe',
                                       'Set-NetFirewallRule -DisplayName \"Bestands- en '
                                       'printerdeling (Echoaanvraag - ICMPv4-In)\" -Profile Any -Enabled True'])
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instelling is niet uitgevoerd!')
            self.infobox('Ping (ICMP) is geactiveerd')
        elif "en" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"File and Printer Sharing '
                                                         '(Echo Request - ICMPv4-In)\" -Profile Any -Enabled True'])
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instelling is niet uitgevoerd!')
            self.infobox('Ping (ICMP) is geactiveerd')

    def firewall_network_discovery(self):
        if "nl" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'netsh advfirewall firewall '
                                                         'set rule group=”Network Discovery” new enable=Yes'])
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instelling is niet uitgevoerd!')
            self.infobox('Network detecteren is geactiveerd')
        elif "en" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'netsh advfirewall firewall '
                                                         'set rule group=”Network Discovery” new enable=Yes'])
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instelling is niet uitgevoerd!')
            self.infobox('Network detecteren is geactiveerd')

    # Functie voor het wijzigen van de computernaam
    def checkout_hostname(self, hostname):
        if len(hostname) > 15 or len(hostname) < 2:
            return False
        prohobited = '\\/_:*?\"<>|. ,~!@#$%^&\'()}{'
        for elem in prohobited:
            if elem in hostname:
                return False
        if hostname.endswith('-'):
            return False
        alphabet = 'abcdefghijklmnopqtrsuvwxyz1234567890'
        if not (hostname[0] in alphabet or hostname[0] in alphabet.upper()):
            return False
        return True

    def set_hostname(self):
        new_hostname = self.lineEdit_hostname.text()
        if not self.checkout_hostname(new_hostname):
            self.add_text_to_log('{} is geen geldige computernaam'.format(new_hostname))
            self.criticalbox('Ongeldige computernaam, zie info button')
            return
        try:
            subprocess.check_call(['powershell.exe', "Rename-Computer -NewName {}".format(new_hostname)])
            self.add_text_to_log('Computernaam is aangepast naar {}'.format(new_hostname))
            self.infobox('De computernaam is aangepast naar: {}'.format(self.lineEdit_hostname.text()))
        except Exception as e:
            self.criticalbox('De uitvoering is mislukt!')
            self.add_text_to_log(str(e))

    # Security
    def import_sec_policy(self):
        secpol_new = resource_path('\\src\\resources\\security\\secpol_new.inf')
        if not os.path.exists(secpol_new):
            self.criticalbox('Kan secpol_new.inf niet vinden \nFunctie kan niet uitgevoerd worden!')
            logging.info('Kan secpol_new.inf niet vinden, import_sec_policy kan niet uitgevoerd worden')
        else:
            current_user_Desktop = 'c:\\users\\{}\\desktop'.format(getpass.getuser())
            program_cwd = os.getcwd()

            # Backup maken van de huidige security policy
            try:
                os.chdir("c:\\windows\\system32")
                subprocess.check_call(['powershell.exe', 'c:\\windows\\system32\\secedit '
                                                         '/export /cfg backup_secpol.inf /log c:\\windows\\system32\\secpol_backup.log /quiet'])
                logging.info('Backup van default security policy is geslaagd')
                try:
                    shutil.copy('backup_secpol.inf', current_user_Desktop)  # Copy secpol_backup to user desktop
                    logging.info('backup_secpol.inf is verplaatst naar {}'.format(current_user_Desktop))
                except Exception as e:
                    self.criticalbox('Kopieeren van backup_secpol.inf is mislukt')
            except Exception as e:
                logging.info('Het maken van de security policy backup is mislukt!\n Foutmelding {}'.format(str(e)))
            finally:
                os.chdir(program_cwd)

            # Testen op een NL systeem
            try:
                # Copy secpol_new to c:\windows\system32
                shutil.copy(secpol_new, 'c:\\windows\\system32')
                # Import secpol_new policy
                try:
                    subprocess.check_call(['powershell.exe', 'c:\\windows\\system32\\secedit /configure '
                                                             '/db c:\\windows\\system32\\defltbase.sdb /cfg {} '
                                                             '/overwrite /log c:\\windows\\system32\\secpol_import.log '
                                                             '/quiet'.format(secpol_new)])
                    logging.info('Import security policy geslaagd')
                    try:
                        subprocess.check_call(['powershell.exe', 'echo y | gpupdate /force /wait:0'])
                        # FIXME: Nagaan of de gebruiker uitgelogd moet worden na het aanpassen van de policy of
                        # FIXME: pas na het doorlopen van het programma
                        # try:
                        #     subprocess.check_call(['powershell.exe', 'shutdown -L'])
                        # except Exception as e:
                        #     logging.info(str(e))
                    except Exception as e:
                        logging.info(str(e))
                except Exception as e:
                    logging.info('Importeren van security policy is mislukt. {}'.format(str(e)))
            except Exception as e:
                logging.info('Het kopieeren van {} naar c:\\windows\\system32 is mislukt!\n '
                             'Foutmelding {}'.format(secpol_new, str(e)))

    # secedit /export /DB %temp%\temp.sdb /cfg %~dp0\secpol_backup.inf /quiet >nul
    # secedit /configure /DB %temp%\temp.sdb /cfg %policy% /overwrite /quiet >nul

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

    def enable_usb(self):
        try:
            register = 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v ' \
                       'Start /t REG_DWORD /d 3 /f'
            subprocess.check_call(register.split(" "))
            self.infobox('USB-opslagapparaten zijn geactiveerd')
            self.usb_check()
        except subprocess.CalledProcessError:
            self.criticalbox('De uitvoering is mislukt')

    def disable_usb(self):
        try:
            register = 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f'
            subprocess.check_call(register.split(" "))
            self.infobox('USB-opslagapparaten zijn gedeactiveerd')
            self.usb_check()
        except subprocess.CalledProcessError:
            self.criticalbox('De uitvoering is mislukt! \n\n Is het programma uitgevoerd als Administrator?')

    # Wimndows settings
    def enable_rdp(self):
        if "nl" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                         'Gebruikersmodus (TCP-In)\" -Profile Any -Enabled True'])
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                         'Gebruikersmodus (UDP-In)\" -Profile Any -Enabled True'])
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                         'Schaduw (TCP-In)\" -Profile Any -Enabled True'])
                logging.info('Firewall instellingen voor RDP zijn geactiveerd')
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instellingen voor RDP zijn niet uitgevoerd')
        elif "en" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                         'User Mode (TCP-In)\" -Profile Any -Enabled True'])
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                         'User Mode (UDP-In)\" -Profile Any -Enabled True'])
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                         'Shadow (TCP-In)\" -Profile Any -Enabled True'])
                logging.info('Firewall instellingen voor RDP zijn geactiveerd')
            except subprocess.CalledProcessError:
                self.criticalbox('De firewall instellingen voor RDP zijn niet uitgevoerd')

        # Register settings for RDP
        register = [
        'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
        '/v fDenyTSConnections /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
        '/v SecurityLayer /t REG_DWORD /d 0 /f',
        'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
        '/v UserAuthentication /t REG_DWORD /d 0 /f']
        for key in register:
            try:
                subprocess.check_call(key)
                logging.info('Register edit: {}'.format(key))
            except subprocess.CalledProcessError:
                logging.info('De register instellingen voor RDP zijn niet uitgevoerd')

    # Log
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
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(resource_path('../resources/ui/about_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))


class LicencePopup(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(resource_path('../resources/ui/licence_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))


class SettingsPopup(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(resource_path('../resources/ui/settings_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))


class HostnamePopup(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(600, 400)
        loadUi(resource_path('../resources/ui/hostname_help_popup.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))


def main():
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())
    windows7_check()

if __name__ == '__main__':
    if is_admin():  # Check admin rights
        main()
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
