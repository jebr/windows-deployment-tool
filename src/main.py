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
import requests
import time
import threading
import functools
import webbrowser
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Table
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors

from PyQt5.QtCore import QDateTime
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem, QLabel
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui, QtCore


try:
    os.chdir(os.path.dirname(sys.argv[0]))
except Exception:
    pass

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


# Software version
current_version = float(2.0)

# Create temp folder
current_user = getpass.getuser()
if not os.path.exists(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT'):
    os.makedirs(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT')

# Set logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log',
                    filemode='a')
date_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
# logging.disable(logging.DEBUG)
# FIXME Console logging alleen voor ontwikkeling, uitzetten bij een release
# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# set a format which is simpler for console use
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

# External files
ui_main_window = resource_path('resources/ui/main_window.ui')
ui_hostname_window = resource_path('resources/ui/hostname_help_dialog.ui')
ui_info_window = resource_path('resources/ui/info_dialog.ui')
ui_license_window = resource_path('resources/ui/license_dialog.ui')
ui_logging_window = resource_path('resources/ui/wdt_logging_dialog.ui')
ui_admin_window = resource_path('resources/ui/admin_dialog.ui')
icon_window = resource_path('icons/wdt.ico')
icon_transparant_image = resource_path('icons/transparent.png')
icon_circle_info = resource_path('icons/circle-info.png')
icon_circle_check = resource_path('icons/circle-check.png')
icon_heijmans_logo = resource_path('icons/heijmans-logo.jpg')
secpol_new = resource_path('resources/security/secpol_new.inf')
energy_config_on = resource_path('resources/energy/energy-full.pow')
energy_config_lock = resource_path('resources/energy/energy-auto-lock.pow')
energy_config_default = resource_path('resources/energy/energy-default.pow')
license_file = resource_path('resources/license/license.txt')

# Release page
def website_update():
    webbrowser.open('https://github.com/jebr/windows-deployment-tool/releases')

def thread(func):
        @functools.wraps(func)
        def wrapper(self, **kwargs):
            if 'daemon' in kwargs:
                daemon = kwargs.pop('daemon')
            else:
                daemon = True
            t = threading.Thread(target=func, args=[self], daemon=daemon)
            t.start()
        return wrapper


class BaseWindow:
    def powershell(self, input_: list) -> str:
        """
        Returns a string when no error
        If an exception occurs the exeption is logged and None is returned
        """
        try:
            proc = subprocess.Popen(['powershell.exe'] + input_,
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    stdin=subprocess.PIPE,
                                    cwd=os.getcwd(),
                                    env=os.environ)
            proc.stdin.close()
            outs, errs = proc.communicate(timeout=15)
            return outs.decode('U8')
        except Exception as e:
            logging.warning(e)

    # Messageboxen
    def infobox(self, message):
        QMessageBox.information(self, 'Info', message, QMessageBox.Ok)

    def warningbox(self, message):
        QMessageBox.warning(self, 'Warning', message, QMessageBox.Close)

    def criticalbox(self, message):
        QMessageBox.critical(self, 'Error', message, QMessageBox.Close)

    def question(self, message):
        QMessageBox.question(self, 'Question', message, QMessageBox.Ok)

    def noicon(self, message):
        QMessageBox.noicon(self, '', message, QMessageBox.Ok)

    def infobox_update(self, message):
        title = f'Windows Deployment Tool v{current_version}'
        buttonReply = QMessageBox.information(self, title, message, QMessageBox.Yes, QMessageBox.No)
        if buttonReply == QMessageBox.Yes:
            webbrowser.open('https://github.com/jebr/windows-deployment-tool/releases')


class MainPage(QtWidgets.QMainWindow, BaseWindow):
    def __init__(self):
        super().__init__()
        loadUi(ui_main_window, self)
        self.setFixedSize(900, 760)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        self.actionAbout.triggered.connect(self.open_info_window)
        self.actionLicence.triggered.connect(self.open_license_window)
        self.actionLogging.triggered.connect(self.open_logging_window)
        self.actionAdministrator_Account.triggered.connect(self.open_admin_window)
        self.actionVersion.setText(f'Version v{current_version}')

        # Controleer systeemtaal
        windll = ctypes.windll.kernel32
        windll.GetUserDefaultUILanguage()
        self.os_language = locale.windows_locale[windll.GetUserDefaultUILanguage()]

        # Controleer windows versie
        self.os_version = platform.platform()

        # Hostname
        self.hostname = os.getenv('COMPUTERNAME')

        # System checks
        self.pushButton_system_check.clicked.connect(self.system_checks)
        self.pushButton_check_secpol.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_secpol.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_rdp.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_rdp.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_usb.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_fw_icmp.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_fw_discovery.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_windows_updates.clicked.connect(self.open_update)
        self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))

        # Pre-system checks
        logging.info(f'========{date_time}========')
        self.new_version = current_version

        if self.check_update_wdt == 'New Version':  # Check for update WDT
            self.infobox_update(f'v{self.new_version} is nu beschikbaar om te installeren.\n Wil je deze nu downloaden?')
            self.statusBar().showMessage(f'Nieuwe versie beschikbaar v{self.new_version}')
            logging.info(f'Initial check: Current software version v{current_version}')
            logging.info(f'Initial check: New version available v{self.new_version}')
        else:
            self.statusBar().showMessage(f'Windows Deployment Tool v{self.new_version}')
            logging.info(f'Initial check: Current software version v{current_version}')

        # Initil checks
        self.windows7_check()
        self.usb_check()
        self.energy_check()

        # Hostname
        self.pushButton_info_hostname.clicked.connect(self.open_hostname_help_window)
        self.pushButton_info_hostname.setIcon(QIcon(QPixmap(icon_circle_info)))
        self.pushButton_info_hostname.setToolTip('Klik voor informatie over computernaam')
        self.label_hostname.setText('Huidige computernaam: {}'.format(os.getenv('COMPUTERNAME')))
        self.pushButton_set_hostname.clicked.connect(self.set_hostname)

        # Import users
        self.pushButton_import_csv.clicked.connect(self.load_csv_file)
        self.pushButton_users_add.clicked.connect(self.add_windows_users)
        self.pushButton_clear_users_table.clicked.connect(self.clear_users_table)

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

        # Energy settings
        self.pushButton_energy_on.clicked.connect(self.energy_on)
        self.pushButton_energy_lock.clicked.connect(self.energy_lock)
        self.pushButton_energy_default.clicked.connect(self.energy_restore)

        # Restart system
        self.pushButton_restart_system.clicked.connect(self.restart_system)

        # Update button
        self.actioncheck_update_wdt.triggered.connect(self.check_update_wdt_trigger)

        # Create report button:
        self.pushButton_export_system_settings.clicked.connect(self.create_pdf_report)

        # Set date for report
        datetime = QDateTime.currentDateTime()
        self.dateEdit_date.setDateTime(datetime)

        # Set counter for started threads
        self.counter_threads = 0

    # Button to check on updates
    def check_update_wdt_trigger(self):
        update_check = self.check_update_wdt()
        if update_check == 'New Version':
            self.infobox_update(
                f'v{self.new_version} is nu beschikbaar om te installeren.\n Wil je deze nu downloaden?')
            self.statusBar().showMessage(f'Nieuwe versie beschikbaar v{self.new_version}')
            logging.info(f'Update button: Current software version v{current_version}')
        if update_check == 'Connection Error':
            self.warningbox('Het is niet mogelijk om te controleren op updates\n\nHerstel de internetverbinding!')
        if update_check == 'Latest Version':
            self.infobox(f'Je maakt momenteel gebruik van de nieuwste versie (v{current_version})')

    # WDT update check
    def check_update_wdt(self):
        url = 'https://raw.githubusercontent.com/jebr/windows-deployment-tool/master/version.txt'
        try:
            resp = requests.get(url, timeout=2)
        except Exception as e:
            logging.error(f'{e}')
            return ('Connection Error')
        if not resp.ok:
            logging.error(f'{resp.status_code}')
            logging.error(f'{resp.text}')
            return ('Connection Error')
        latest_version = float(resp.text)
        self.new_version = latest_version
        if latest_version > current_version:
            return ('Latest Version')
        return ('New Version')

    @thread
    def system_checks(self):
        self.counter_threads = 0
        self.pushButton_system_check.setEnabled(False)

        self.windows_chars()
        self.secpol_check()
        self.rdp_check()
        self.fw_icmp_check()
        self.fw_discovery_check()
        self.energy_check()
        self.get_users()

        while True:
            # print(self.counter_threads)
            if self.counter_threads == 7:  # Verhogen als er meer threads in
                # deze functie geplaatst worden
                break
            time.sleep(0.05)
        self.pushButton_export_system_settings.setEnabled(True)
        self.pushButton_system_check.setEnabled(True)

    @thread
    def windows7_check(self):
        os_version = platform.platform()
        if "Windows-7" in os_version:
            self.warningbox('Windows 7 wordt niet meer ondersteund\nDe applicatie zal afgesloten worden')
            logging.error(f'Initial check: Windows 7 is not supported')
            sys.exit()

    @thread
    def energy_check(self):
        energy_on_scheme = '00000000-0000-0000-0000-000000000000'
        energy_lock_scheme = '39ff2e23-e11c-4fc3-ab0f-da25fadb8a89'

        active_scheme = self.powershell(['powercfg /getactivescheme'])

        if energy_on_scheme in active_scheme:
            self.label_energie_settings.setText('Altijd aan')
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('Initial check: Energy plan - Always on')
        elif energy_lock_scheme in active_scheme:
            self.label_energie_settings.setText('Automatisch vergrendelen')
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('Initial check: Energy plan - Lock automatically')
        else:
            self.label_energie_settings.setText('Standaard energieplan')
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('Initial check: Energy plan - Default')
        self.counter_threads += 1

    @thread
    def secpol_check(self):
        if os.path.exists('c:\\windows\\system32\secpol_new.inf'):
            self.pushButton_check_secpol.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_secpol.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('System check: Security policy applied ')
            self.secpol_check_return = True
        else:
            self.secpol_check_return = False
            logging.info('System check: Security policy not applied')
        self.counter_threads += 1

    @thread
    def rdp_check(self):
        self.rdp_register_path = 'Registry::"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"'
        self.rdp_reg_dword = "fDenyTSConnections"
        # Controleer de waarde van het register
        self.check_rdp = self.powershell([f'Get-ItemProperty -Path {self.rdp_register_path} -Name {self.rdp_reg_dword}'])
        if "0" in self.check_rdp:
            self.pushButton_check_rdp.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_rdp.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('System check: RDP activated')
            self.rdp_check_return = True
        else:
            self.rdp_check_return = False
            logging.info('System check: RDP not activated')
        self.counter_threads += 1

    @thread
    def fw_icmp_check(self):
        icmp_rule_nl = str('Get-NetFirewallRule -DisplayName \"Bestands- en printerdeling '
                           '(Echoaanvraag - ICMPv4-In)\" | select DisplayName, Enabled')
        icmp_rule_en = str('Get-NetFirewallRule -DisplayName \"File and Printer Sharing '
                           '(Echo Request - ICMPv4-In)\" | select DisplayName, Enabled')
        if "nl" in self.os_language:
            try:
                check_nl = self.powershell([icmp_rule_nl])
                # check_nl = str(subprocess.check_output(['powershell.exe', icmp_rule_nl]))
                if "True" in check_nl:
                    self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                    logging.info('System check: Firewall ICMP allowed')
                    self.fw_icmp_check_return = True
                else:
                    self.fw_icmp_check_return = False
                    logging.info('System check: Firewall ICMP blocked')
            except Exception as e:
                logging.info(f'System check: Firewall ICMP check failed with message: {e}')
        else:
            try:
                check_en = self.powershell([icmp_rule_en])
                # check_en = str(subprocess.check_output(['powershell.exe', icmp_rule_en]))
                if "True" in check_en:
                    self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                    logging.info('System check: Firewall ICMP allowed')
                    self.fw_icmp_check_return = True
                else:
                    self.fw_icmp_check_return = False
                    logging.info('System check: Firewall ICMP blocked')
            except Exception as e:
                logging.info(f'System check: Firewall ICMP check failed with message {e}')
        self.counter_threads += 1

    @thread
    def fw_discovery_check(self):
        # Netwerk detecteren (NB-Datagram-In)
        # Network Discovery (NB-Datagram-In)
        if "nl" in self.os_language:
            try:
                check_nl = self.powershell(['Get-NetFirewallRule -DisplayName "Netwerk detecteren (NB-Datagram-In)" '
                                            '| select DisplayName, Enabled'])
                check_true = check_nl.count("True")
                if check_true == 3:
                    self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                    logging.info('System check: Firewall discovery allowed')
                    self.fw_discovery_check_return = True
                else:
                    self.fw_discovery_check_return = False
                    logging.info('System check: Firewall discovery blocked')
            except Exception as e:
                logging.info(f'System check: Firewall discovery check failed with message: {e}')
        else:
            try:
                check_en = self.powershell(['Get-NetFirewallRule -DisplayName "Network Discovery (NB-Datagram-In)" '
                                            '| select DisplayName, Enabled'])
                check_true = check_en.count("True")
                if check_true == 3:
                    self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                    logging.info('System check: Firewall discovery allowed')
                    self.fw_discovery_check_return = True
                else:
                    self.fw_discovery_check_return = False
                    logging.info('System check: Firewall discovery blocked')
            except Exception as e:
                logging.info(f'System check: Firewall discovery check failed with message: {e}')
        self.counter_threads += 1

    @thread
    def windows_chars(self):
        w_version = self.powershell(['(Get-WmiObject -class '
                                         'Win32_OperatingSystem).Caption'])
        self.label_windows_version.setText(w_version.rstrip())
        self.label_windows_version.setToolTip(w_version.rstrip())
        logging.info(f'System check: Windows version - {w_version.rstrip()}')

        if 'nl' in self.os_language:
            self.label_windows_lang.setText('Nederlands')
            self.label_windows_lang.setToolTip('Nederlands')
            logging.info(f'System check: Language - Dutch')
        elif 'en' in self.os_language:
            self.label_windows_lang.setText('Engels')
            self.label_windows_lang.setToolTip('Engels')
            logging.info(f'System check: Language - English')
        else:
            self.label_windows_lang.setText(self.os_language)
            self.label_windows_lang.setToolTip(self.os_language)
            logging.info(f'System check: Language {self.os_language}')

        # Domain / Workgroup check
        w_domain_workgroup = self.powershell(['(Get-WmiObject Win32_ComputerSystem).domain'])
        self.label_domain_workgroup.setText(w_domain_workgroup.rstrip())
        self.label_domain_workgroup.setToolTip(w_domain_workgroup.rstrip())
        logging.info(f'System check: Workgroup / Domain - {w_domain_workgroup.rstrip()}')

        # Get Hostname
        windows_hostname = os.getenv('COMPUTERNAME')
        self.label_windows_hostname.setText(windows_hostname)
        self.label_windows_hostname.setToolTip(windows_hostname)
        logging.info(f'System check: Hostname - {windows_hostname}')

        # Get Manufacturer and model
        manufacturer = self.powershell(['(get-wmiobject Win32_ComputerSystem).manufacturer'])
        model = self.powershell(['(get-wmiobject Win32_ComputerSystem).model'])
        self.label_manufacturer_model.setText(f'{manufacturer.rstrip()} / {model.rstrip()}')
        self.label_manufacturer_model.setToolTip(f'{manufacturer.rstrip()} / {model.rstrip()}')
        logging.info(f'System check: Manufacturer / Model - {manufacturer.rstrip()} / {model.rstrip()}')

        # Get PC Type
        type_number = self.powershell(['(get-wmiobject Win32_ComputerSystem).PCSystemTypeEx'])
        type_number = int(type_number.rstrip())
        if type_number == 1:
            self.label_type.setText('Desktop')
            self.label_type.setToolTip('Desktop')
            logging.info('System check: Computer type - Desktop')
        elif type_number == 2:
            self.label_type.setText('Mobile / Laptop')
            self.label_type.setToolTip('Mobile / Laptop')
            logging.info('System check: Computer type - Mobile / Laptop')
        elif type_number == 3:
            self.label.type.setText('Workstation')
            self.label_type.setToolTip('Workstation')
            logging.info('System check: Computer type - Workstation')
        elif type_number == 4:
            self.label_type.setText('Enterprise Server')
            self.label_type.setToolTip('Enterprise Server')
            logging.info('System check: Computer type - Server')
        elif type_number == 5:
            self.label_type.setText('Small Office Server (SOHO)')
            self.label_type.setToolTip('Small Office Server (SOHO)')
            logging.info('System check: Computer type - Small Office Server')
        elif type_number == 6:
            self.label_type.setText('Appliance PC')
            self.label_type.setToolTip('Appliance PC')
            logging.info('System check: Computer type - Appliance PC')
        elif type_number == 7:
            self.label_type.setText('Performance Server')
            self.label_type.setToolTip('Performance Server')
            logging.info('System check: Computer type - Performance Server')
        elif type_number == 8:
            self.label_type.setText('Maximum')
            self.label_type.setToolTip('Maximum')
            logging.info('System check: Computer type - Maximum')
        else:
            self.label_type('Onbekend product type')
            self.label_type.setToolTip('Onbekend product type')
            logging.info('System check: Computer type - Unknown')

        # Calculate RAM
        bytes_number = self.powershell(['(get-wmiobject '
                                        'Win32_ComputerSystem).totalphysicalmemory'])
        bytes_number = int(bytes_number)
        gb_number = bytes_number / (1024 ** 3)
        gb_number = round(gb_number)
        self.label_physicalmemory.setText(f'{gb_number} GB')
        self.label_physicalmemory.setToolTip(f'{gb_number} GB')
        logging.info(f'System check: RAM {gb_number} GB')

        # Get Processor info
        processor_name = self.powershell(['(get-wmiobject Win32_Processor).name'])
        self.label_processor.setText(processor_name.rstrip())
        self.label_processor.setToolTip(processor_name.rstrip())
        logging.info(f'System check: Processor - {processor_name.rstrip()}')
        processor_cores = self.powershell(['(get-wmiobject Win32_Processor).NumberOfCores'])
        processor_logicalprocessors = self.powershell(['(get-wmiobject Win32_Processor).NumberOfLogicalProcessors'])
        self.label_cores.setText(f'{processor_cores.rstrip()} cores / {processor_logicalprocessors.rstrip()} logical processors')
        self.label_cores.setToolTip(f'{processor_cores.rstrip()} cores / {processor_logicalprocessors.rstrip()} logical processors')
        logging.info(f'System check: Processor cores - {processor_cores.rstrip()} cores / {processor_logicalprocessors.rstrip()} logical processors')

        # Get Windows Build and Version
        w_release_id = self.powershell(
            ['(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseID'])
        w_release_version = self.powershell(
            ['(Get-WmiObject Win32_OperatingSystem).Version'])
        self.label_windows_build.setText(f'{w_release_version.rstrip()} / {w_release_id.rstrip()}')
        self.label_windows_build.setToolTip(f'{w_release_version.rstrip()} / {w_release_id.rstrip()}')
        logging.info(f'System check: Windows build - {w_release_version.rstrip()} / {w_release_id.rstrip()}')
        self.counter_threads += 1

    def open_update(self):
        try:
            self.powershell(['C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate'])
        except Exception as e:
            logging.info('Openen Windows update is mislukt.')

    @thread
    def get_users(self):
        w_users = self.powershell(['Get-LocalUser | select name, enabled'])
        w_users_output = w_users.splitlines()
        w_group_admin = self.powershell(['net localgroup administrators'])
        self.tableWidget_active_users.clearContents()
        i = 0
        for user in w_users_output:
            if 'True' in user:
                new_user = user.replace('True', "").replace(" ", "")
                self.tableWidget_active_users.setItem(i, 0, QTableWidgetItem(new_user))
                if new_user in w_group_admin:
                    self.tableWidget_active_users.setItem(i, 1, QTableWidgetItem('Ja'))
                else:
                    self.tableWidget_active_users.setItem(i, 1, QTableWidgetItem('Nee'))
                i += 1
        self.counter_threads += 1

    @thread
    def firewall_ping(self):
        if "nl" in self.os_language:
            try:
                self.powershell(['Set-NetFirewallRule -DisplayName \"Bestands- en '
                                       'printerdeling (Echoaanvraag - ICMPv4-In)\" -Profile Any -Enabled True'])
                self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                logging.info('Firewall ICMP activated')
            except Exception as e:
                logging.error(f'Firewall ICMP failed with message: {e}')
        else:
            try:
                self.powershell(['Set-NetFirewallRule -DisplayName \"File and Printer Sharing '
                                                         '(Echo Request - ICMPv4-In)\" -Profile Any -Enabled True'])
                self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                logging.info('Firewall ICMP activated')
            except Exception as e:
                logging.error(f'Firewall ICMP failed with message: {e}')

    @thread
    def firewall_network_discovery(self):
        if "nl" in self.os_language:
            try:
                self.powershell(['netsh advfirewall firewall '
                                                         'set rule group=”Network Discovery” new enable=Yes'])
                self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                logging.info('Firewall Discovery activated')
            except Exception as e:
                logging.error(f'Firewall Discovery failed with message: {e}')
        else:
            try:
                self.powershell(['netsh advfirewall firewall '
                                                         'set rule group=”Network Discovery” new enable=Yes'])
                self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                logging.info('Firewall Discovery activated')
            except Exception as e:
                logging.error(f'Firewall Discovery failed with message: {e}')
    
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

    @thread
    def set_hostname(self):
        new_hostname = self.lineEdit_hostname.text()
        self.hostname = new_hostname
        if not self.checkout_hostname(new_hostname):
            self.criticalbox('Ongeldige computernaam, zie info button')
            return
        try:
            self.powershell([f'Rename-Computer -NewName {new_hostname}'])
            # subprocess.check_call(['powershell.exe', f'Rename-Computer -NewName {new_hostname}'])
            self.label_hostname_new.setText(f'Nieuwe computernaam: {new_hostname}')
            self.lineEdit_hostname.clear()
            logging.info(f'Hostname changed to: {new_hostname}')
        except Exception as e:
            logging.error(f'Hostname change failed with message: {e}')

    # Security
    @thread
    def import_sec_policy(self):
        global secpol_new
        if not os.path.exists(secpol_new):
            self.criticalbox('Kan secpol_new.inf niet vinden \nFunctie kan niet uitgevoerd worden!')
            logging.info('secpol_new.inf is not found on the system. Execution of security policy failed')
        else:
            current_user_Desktop = 'c:\\users\\{}\\desktop'.format(getpass.getuser())
            program_cwd = os.getcwd()

            # Backup maken van de huidige security policy
            try:
                os.chdir("c:\\windows\\system32")
                self.powershell(['c:\\windows\\system32\\secedit '
                                                         '/export /cfg backup_secpol.inf /log c:\\windows\\system32\\secpol_backup.log /quiet'])
                logging.info('Backup of default security policy succesful')
                try:
                    shutil.copy('backup_secpol.inf', current_user_Desktop)  # Copy secpol_backup to user desktop
                    logging.info(f'backup_secpol.inf is moved to {current_user_Desktop}')
                except Exception as e:
                    self.criticalbox('Copy of backup_secpol.inf failed with message: {e}')
            except Exception as e:
                logging.info(f'Backup of security policy failed with message: {e}')
            finally:
                os.chdir(program_cwd)

            # Testen op een NL systeem
            try:
                # Copy secpol_new to c:\windows\system32
                shutil.copy(secpol_new, 'c:\\windows\\system32')
                # Import secpol_new policy
                try:
                    self.powershell([f'c:\\windows\\system32\\secedit /configure '
                                                             f'/db c:\\windows\\system32\\defltbase.sdb /cfg {secpol_new} '
                                                             f'/overwrite /log c:\\windows\\system32\\secpol_import.log '
                                                             f'/quiet'])
                    logging.info('Import security policy succesful')
                    try:
                        self.powershell(['echo y | gpupdate /force /wait:0'])
                        self.pushButton_check_secpol.setIcon(QIcon(QPixmap(icon_circle_check)))
                        # FIXME: Nagaan of de gebruiker uitgelogd moet worden na het aanpassen van de policy of
                        # FIXME: pas na het doorlopen van het programma
                        # try:
                        #     subprocess.check_call(['powershell.exe', 'shutdown -L'])
                        # except Exception as e:
                        #     logging.info(str(e))
                        logging.info('GPUpdate forced succesful')
                    except Exception as e:
                        logging.error(f'GPUpdate failed with message: {e}')
                except Exception as e:
                    logging.info(f'Import security policy failed with message: {e}')
            except Exception as e:
                logging.error(f'Copy of {secpol_new} to c:\\windows\\system32 failed with message: {e}')

    # Functie voor het contoleren van de USB activering
    @thread
    def usb_check(self):
        self.usb_register_path = "Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
        self.usb_reg_dword = "Start"
        # Controleer de waarde van het register
        self.check_usb = self.powershell([f'Get-ItemProperty -Path {self.usb_register_path} -Name {self.usb_reg_dword}'])
        # self.check_usb = str(subprocess.check_output(['powershell.exe', 'Get-ItemProperty -Path {} -Name {}'.format(self.usb_register_path, self.usb_reg_dword)]))
        # Als de waarde 3 is de USB geactiveerd
        if "3" in self.check_usb:
            self.pushButton_usb_enable.setDisabled(True)
            self.pushButton_usb_disable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_transparant_image)))
            logging.info('Initial check: USB-storage Enabled')
            self.usb_check_return = False
        # Als de waarde 4 is de USB gedeactiveerd
        elif "4" in self.check_usb:
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('Initial check: USB-storage Disabled')
            self.usb_check_return = True
        else:
            self.usb_check_return = False
            logging.error('USB-storage check failed. Value of register doesn\'t match number 3 or 4.')

    @thread
    def enable_usb(self):
        try:
            self.powershell(['reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet'
                                                     '\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f'])
            self.pushButton_usb_enable.setDisabled(True)
            self.pushButton_usb_disable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_transparant_image)))
            logging.info('USB-storage enabled')
        except Exception as e:
            logging.error(f'Enable USB-storage failed with message: {e}')

    @thread
    def disable_usb(self):
        try:
            self.powershell(['reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet'
                                                     '\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f'])
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_circle_check)))
            logging.info('USB-storage disabled')
        except Exception as e:
            self.criticalbox(f'Disable USB-storage failed with message: {e}')

    # Wimndows settings
    @thread
    def enable_rdp(self):
        if self.rdp_check():
            logging.info('RDP is al geactiveerd op deze computer')
            return
        else:
            if "nl" in self.os_language:
                try:
                    self.powershell(['Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                             'Gebruikersmodus (TCP-In)\" -Profile Any -Enabled True'])
                    self.powershell(['Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                             'Gebruikersmodus (UDP-In)\" -Profile Any -Enabled True'])
                    self.powershell(['Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                             'Schaduw (TCP-In)\" -Profile Any -Enabled True'])
                    logging.info('Firewall instellingen voor RDP zijn geactiveerd')
                except Exception as e:
                    logging.error(f'Firewall settings RDP failed with message: {e}')
            elif "en" in self.os_language:
                try:
                    self.powershell(['Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                             'User Mode (TCP-In)\" -Profile Any -Enabled True'])
                    self.powershell(['Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                             'User Mode (UDP-In)\" -Profile Any -Enabled True'])
                    self.powershell(['Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                             'Shadow (TCP-In)\" -Profile Any -Enabled True'])
                    logging.info('Firewall instellingen voor RDP zijn geactiveerd')
                except Exception as e:
                    logging.error(f'Firewall settings RDP failed with message: {e}')
            try:
                self.powershell(['reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'])
                self.powershell(['reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\" /v SecurityLayer /t REG_DWORD /d 0 /f'])
                self.powershell(['reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f'])
                logging.info('De register wijzigingen voor RDP zijn geslaagd')
                self.pushButton_check_rdp.setIcon(QIcon(QPixmap(icon_circle_check)))
            except Exception as e:
                logging.error(f'Register settings for RDP failed with message: {e}')

    # Energy Settings
    @thread
    def energy_on(self):
        global energy_config_on
        energy_on_scheme = '00000000-0000-0000-0000-000000000000'

        scheme_list = self.powershell(['powercfg /list'])

        active_scheme = self.powershell(['powercfg /getactivescheme'])

        # Check active scheme
        if energy_on_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
            return

        if energy_on_scheme in scheme_list:
            try:
                self.powershell([f'powercfg /delete {energy_on_scheme}'])
                try:
                    self.powershell([f'powercfg -import {energy_config_on} {energy_on_scheme}'])
                    self.powershell([f'powercfg -setactive {energy_on_scheme}'])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    logging.info('Energy plan: always on activated')
                except Exception as e:
                    logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                self.powershell([f'powercfg -import {energy_config_on} {energy_on_scheme}'])
                self.powershell([f'powercfg -setactive {energy_on_scheme}'])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                logging.info('Energy plan: always on activated')
            except Exception as e:
                logging.error(f'Import energy plan failed with message {e}')
                
    @thread
    def energy_lock(self):
        global energy_config_lock
        energy_lock_scheme = '39ff2e23-e11c-4fc3-ab0f-da25fadb8a89'

        scheme_list = self.powershell(['powercfg /list'])

        active_scheme = self.powershell(['powercfg /getactivescheme'])

        # Check active scheme
        if energy_lock_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
            return

        if energy_lock_scheme in scheme_list:
            try:
                self.powershell([f'powercfg /delete {energy_lock_scheme}'])
                try:
                    self.powershell([f'powercfg -import {energy_config_lock} {energy_lock_scheme}'])
                    self.powershell([f'powercfg -setactive {energy_lock_scheme}'])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
                    logging.info('Energy plan: Auto lock activated')
                except Exception as e:
                    logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                self.powershell([f'powercfg -import {energy_config_lock} {energy_lock_scheme}'])
                self.powershell([f'powercfg -setactive {energy_lock_scheme}'])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
                logging.info('Energy plan: Auto lock activated')
            except Exception as e:
                logging.error(f'Import energy plan failed with message {e}')

    @thread
    def energy_restore(self):
        global energy_config_default
        energy_default_scheme = '381b4222-f694-41f0-9685-ff5bb260df2e'

        scheme_list = self.powershell(['powercfg /list'])

        active_scheme = self.powershell(['powercfg /getactivescheme'])

        # Check active scheme
        if energy_default_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
            return

        if energy_default_scheme in scheme_list:
            try:
                self.powershell([f'powercfg /delete {energy_default_scheme}'])
                try:
                    self.powershell([f'powercfg -import {energy_config_default} {energy_default_scheme}'])
                    self.powershell([f'powercfg -setactive {energy_default_scheme}'])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    logging.info('Energy plan: Default activated')
                except Exception as e:
                    logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                self.powershell([f'powercfg -import {energy_config_default} {energy_default_scheme}'])
                self.powershell([f'powercfg -setactive {energy_default_scheme}'])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                logging.info('Energy plan: Default activated')
            except Exception as e:
                logging.error(f'Import energy plan failed with message {e}')

    # Restart system
    def restart_system(self):
        try:
            self.powershell(['shutdown -r -t 10'])
            self.infobox('Het systeeem zal over 10 seconden herstarten')
        except Exception as e:
            self.warningbox('Door een onbekende fout kan het systeem niet herstart worden\nProbeer het systeem handmatig te herstarten')
            logging.info('Systeem kan niet herstart worden. {}'.format(e))

    # Add Local Windows Users
    def load_csv_file(self):
        self.clear_users_table()
        fileName, _ = QFileDialog.getOpenFileName(self,
            "selecteer cvs bestand", "", "csv (*.csv)")
        if not fileName:
            # If window is clicked away
            return
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
                        if j == 4:
                            if row[j].lower() == 'ja':
                                self.tableWidget_add_users.setItem(i, j, QTableWidgetItem('Ja'))
                            else:
                                self.tableWidget_add_users.setItem(i, j, QTableWidgetItem('Nee'))
                        else:
                            self.tableWidget_add_users.setItem(i,j, QTableWidgetItem(row[j]))
                    i += 1
            except Exception as e:
                self.warningbox('Let op, bestand niet geimporteerd')

    # creating a tw cell (voor functie get_local_users)
    def cell(self, var=""):
        item = QtWidgets.QTableWidgetItem()
        item.setText(var)
        return item

    # Function for later use
    @thread
    def get_local_users(self):
        # w_users_full = subprocess.check_output(['powershell.exe', 'Get-LocalUser | select name, enabled, description'])
        w_users = self.powershell(['(Get-LocalUser).name']).splitlines()
        w_users_enabled = self.powershell(['(Get-LocalUser).enabled']).splitlines()
        w_users_desc = self.powershell(['(Get-LocalUser).description']).splitlines()
        w_users_fullname = self.powershell(['(get-wmiobject -class Win32_USeraccount).fullname']).splitlines()
        w_group_admin = self.powershell(['net localgroup administrators'])
        self.tableWidget_add_users.clearContents()
        i = 0

        # Diable cell voor gevonden gerbuikers
        # item = self.cell("text")
        # item.setFlags(QtCore.Qt.ItemIsEnabled)

        for j in range(len(w_users)):
            user = w_users[j]
            enabled = w_users_enabled[j]
            desc = w_users_desc[j]
            fullname = w_users_fullname[j]
            if enabled == 'False':
                continue
            self.tableWidget_add_users.setItem(i, 0, QTableWidgetItem(user))
            self.tableWidget_add_users.setItem(i, 1, QTableWidgetItem('********'))
            self.tableWidget_add_users.setItem(i, 2, QTableWidgetItem(fullname))
            self.tableWidget_add_users.setItem(i, 3, QTableWidgetItem(desc))
            # execute the line below to every item you need locked
            # self.tableWidget_add_users.setItem(i, 0, item)
            if user in w_group_admin:
                self.tableWidget_add_users.setItem(i, 4, QTableWidgetItem('Ja'))
            else:
                self.tableWidget_add_users.setItem(i, 4, QTableWidgetItem('Nee'))
            self.tableWidget_add_users.setEnabled(False)

            i += 1

    def add_windows_users(self):
        w_users = self.powershell(['(Get-LocalUser).name']).splitlines()
        w_users = [element.lower() for element in w_users]  # Gebruikers naar lowercase
        for i in range(20):
            empty_fields = []
            try:
                user = self.tableWidget_add_users.item(i, 0).text().lower()
                if not user: raise
            except Exception as e:
                empty_fields.append('Gebruikersnaam')
            try:
                password = self.tableWidget_add_users.item(i, 1).text()
                if not password: raise
            except Exception as e:
                empty_fields.append('Wachtwoord')
            try:
                fullname = self.tableWidget_add_users.item(i, 2).text()
                if not fullname: raise
            except Exception as e:
                empty_fields.append('Volledige naam')
            try:
                desc = self.tableWidget_add_users.item(i, 3).text()
                if not desc: raise
            except Exception as e:
                empty_fields.append('Beschrijving')
            try:
                admin = self.tableWidget_add_users.item(i, 4).text()
                if not admin: raise
            except Exception as e:
                empty_fields.append('Administrator')

            if len(empty_fields) == 5:
                continue

            if empty_fields:
                self.warningbox(f'De volgende velden zijn niet ingevuld in rij {i+1}: ' + ', '.join(empty_fields))
                continue

            # Admin veld Ja/ja en anders nee
            admin = True if admin.lower() == 'ja' else False

            if not self.checkout_username(user):
                self.criticalbox(self.username_fault)
                continue

            # Check of de gebruiker al voorkomt op de computer
            if user.lower() in w_users:
                self.warningbox(f'De gebruiker "{user}" komt al voor op deze computer en kan niet toegevoegd. '
                                f'Verander de gebruikersnaam.')
                return False
            try:
                user = user.replace(' ', '')
                user = user.capitalize()
                self.powershell([f'net user "{user}" "{password}" /add /active:yes '
                                                         f'/fullname:"{fullname}" /comment:"{desc}" /expires:never /Y'])
                self.powershell([f'wmic useraccount where "name=\'{user}\'" set PasswordExpires=False '])
                # subprocess.check_call(['powershell.exe', f'$password = {password} -AsSecureString && New-LocalUser "{user}" -Password $password -Fullname {fullname} -Description {desc}'])
                self.tableWidget_add_users.setItem(i, 0, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 1, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 2, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 3, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 4, QTableWidgetItem(''))
                if admin == True:
                    try:
                        self.powershell([f'Add-LocalGroupMember -Group "Administrators" -Member {user}'])
                    except Exception as e:
                        logging.error(f'User {user} can not be added to the administrators group. Error message: {e}')
                logging.info(f'User {user} is successfully added as local user to this computer')
            except Exception as e:
                logging.error(f'User {user} can not be added. Error message: {e}')

    def checkout_username(self, username):
        self.username_fault = ''
        if len(username) > 20:
            self.username_fault = ('De gebruikersnaam bevat teveel karakters. Maximaal 20 karakters toegestaan')
            return False
        prohobited = '\\/:*?\"<>|,@[];=+'
        # " / \ [ ] : ; | = , + * ? < > @
        for elem in prohobited:
            if elem in username:
                self.username_fault = ('De gebruikersnaam bevat ongeldige tekens.')
                return False
        if username.replace(' ','') == '':
            self.username_fault = ('De gebruikersnaam mag niet uit spaties bestaan.')
            return False
        if username.replace('.','.') == '.':
            self.username_fault = ('De gebruikersnaam mag niet uit punten bestaan.')
            return False
        if username.lower() == self.powershell(['hostname']).lower().rstrip():
            self.username_fault = ('De gebruikersnaam mag niet hetzelfde zijn als de computernaam.')
            return False
        if username.lower().endswith(' '):
            self.username_fault = ('De gebruikersnaam mag niet eindigen met een spatie')
            return False
        if username.lower().startswith(' '):
            self.username_fault = ('De gebruikersnaam mag niet beginnen met een spatie')
            return False
        return True

    def checkout_password(self, password):
        self.password_fault = ''
        if len(password) < 10:
            self.password_fault = ('Password voldoet niet aan de eisen.\nMinimaal 10 karakters')
            return False
        alphabet = 'abcdefghijklmnopqtrsuvwxyz1234567890'
        if (password in alphabet or password in alphabet.upper()):
            self.password_fault = ('Password voldoet niet aan de eisen.\nMinimaal 1 symbool')
            return False
        return True

    def clear_users_table(self):
        self.tableWidget_add_users.clearContents()

    def create_pdf_report(self):
        if not self.lineEdit_project.text():
            self.warningbox('Vul de naam van het project in')
            logging.error('Project field not filled in')
            return False
        elif not self.lineEdit_engineer.text():
            self.warningbox('Vul je voor- en achternaam in')
            logging.error('Engineer field not filled in')
            return False
        else:
            self.create_pdf_report_thread()

    @thread
    def create_pdf_report_thread(self):
        date_time = datetime.now().strftime('%d%m%Y%H%M%S')
        hostname = self.hostname
        project = self.lineEdit_project.text()
        engineer = self.lineEdit_engineer.text()
        filename = f'c:\\users\\{current_user}\\Desktop\\deploy_report_{project}_{hostname}.pdf'

        try:
            my_canvas = canvas.Canvas(filename)

            styles = getSampleStyleSheet()
            width, height = A4

            # Header
            my_canvas.drawImage(icon_heijmans_logo, 400, 770, 156.35, 39.6)

            logo_sub_text = f'''
            <font size=10 color=gray>UTILITEIT SAFETY & SECURITY</font>
            '''
            para_logo_sub = Paragraph(logo_sub_text, style=styles['Normal'])
            para_logo_sub.wrapOn(my_canvas, width, height)
            para_logo_sub.drawOn(my_canvas, 400, 755)

            # Body
            # Project data
            project_data = f'''
            <font size=24><b>Deployment rapportage</b></font><br/>
            <br/>
            <br/>
            <font size=16><b>{self.lineEdit_project.text()}</b><br/></font>
            <font size=12 color=gray>Server / Workstation: {hostname}</font>
            '''
            para_project_data = Paragraph(project_data, style=styles['Normal'])
            para_project_data.wrapOn(my_canvas, width, height)
            para_project_data.drawOn(my_canvas, 50, 600)

            character_data = f'''
            <font size=10 color=gray>
            Kenmerk: {date_time}-{hostname} <br/>
            <br/>
            Datum: {self.dateEdit_date.text()}<br/>
            <br/>
            Engineer: {self.lineEdit_engineer.text()}<br/>
            </font>
            '''
            para_character_data = Paragraph(character_data, style=styles['Normal'])
            para_character_data.wrapOn(my_canvas, width, height)
            para_character_data.drawOn(my_canvas, 50, 175)

            # Footer
            footer_text = '''
            <font size=6>Heijmans Utiliteit B.V. • Graafsebaan 65, 5248 JT  Rosmalen • Postbus 246, 5240 AE  Rosmalen • 
            Nederland<br/> 
            Telefoon +31 (0)73 543 51 11 • E-mail info@heijmans.nl • www.heijmans.<br/>
            Niets van dit rapport en/of ontwerp mag worden vermenigvuldigd, openbaar gemaakt en/of overhandigd aan derden, 
            zonder voorafgaande schriftelijke toestemming van de samensteller.</font>
            '''
            para_footer = Paragraph(footer_text, style=styles['Normal'])
            para_footer.wrapOn(my_canvas, width, height)
            para_footer.drawOn(my_canvas, 50, 20)
            # Page number
            para_page_number_1 = Paragraph('<font size=6>pagina 1 van 2</font>', style=styles['Normal'])
            para_page_number_1.wrapOn(my_canvas, width, height)
            para_page_number_1.drawOn(my_canvas, width / 2, 5)

            # Page Break
            my_canvas.showPage()

            # Page 2
            # Header
            my_canvas.drawImage(icon_heijmans_logo, 400, 770, 156.35, 39.6)
            para_logo_sub.drawOn(my_canvas, 400, 755)

            # Body
            # System info
            title_system_info = Paragraph('<font size=14><b>Windows Informatie</b></font>', style=styles['Normal'])
            title_system_info.wrapOn(my_canvas, width, height)
            title_system_info.drawOn(my_canvas, 50, 700)
            system_info_data = [
                ['Windows versie', str(self.label_windows_version.text())],
                ['Windows Taal', str(self.label_windows_lang.text())],
                ['Domein / Werkgroep', self.label_domain_workgroup.text()],
                ['Computernaam', self.label_windows_hostname.text()],
                ['Fabrikant / Model', self.label_manufacturer_model.text()],
                ['Type', self.label_type.text()],
                ['RAM', self.label_physicalmemory.text()],
                ['Processor', self.label_processor.text()],
                ['Core / Logical Processors', self.label_cores.text()],
                ['Windows Build', self.label_windows_build.text()]
            ]
            table_system_info = Table(system_info_data, style=[('OUTLINE', (0,0), (-1,-1), 0.25, colors.black),
                                                               ('LINEAFTER', (0,0), (0,-1), 0.25, colors.black)], colWidths=250)
            table_system_info.wrapOn(my_canvas, width, height)
            table_system_info.drawOn(my_canvas, 50, 510)

            # Application Settings
            title_application_settings = Paragraph('<font size=14><b>Applicatie instellingen</b></font>', style=styles['Normal'])
            title_application_settings.wrapOn(my_canvas, width, height)
            title_application_settings.drawOn(my_canvas, 50, 490)

            secpol_enabled = 'Ja' if self.secpol_check_return else 'Nee'
            usb_blocked = 'Ja' if self.usb_check_return else 'Nee'
            rdp_enabled = 'Ja' if self.rdp_check_return else 'Nee'
            icmp_enabled = 'Ja' if self.fw_icmp_check_return else 'Nee'
            discovery_enabled = 'Ja' if self.fw_discovery_check_return else 'Nee'

            application_settings_data = [
                ['Security Policy toegepast', secpol_enabled],
                ['USB geblokkeerd', usb_blocked],
                ['Remote Desktop geactiveerd', rdp_enabled],
                ['Windows Firewall ICMP toegestaan', icmp_enabled],
                ['Windows Firewall Discovery toegestaan', discovery_enabled],
                ['Energiebeheer', self.label_energie_settings.text()]
            ]
            table_application_settings = Table(application_settings_data, style=[('OUTLINE', (0, 0), (-1, -1), 0.25, colors.black),
                                                                                 ('LINEAFTER', (0, 0), (0, -1), 0.25, colors.black)], colWidths=250)
            table_application_settings.wrapOn(my_canvas, width, height)
            table_application_settings.drawOn(my_canvas, 50, 372)

            # Windows Users
            title_windows_users = Paragraph('<font size=14><b>Lokale Windows Gebruikers</b></font>', style=styles['Normal'])
            title_windows_users.wrapOn(my_canvas, width, height)
            title_windows_users.drawOn(my_canvas, 50, 352)

            windows_users_data = [['Gebruiker', 'Administrator']]
            height_windows_users_table = 318
            for i in range(20):
                try:
                    user_cell = self.tableWidget_active_users.item(i, 0)
                    admin_cell = self.tableWidget_active_users.item(i, 1)
                    if 'text' not in dir(user_cell) or 'text' not in dir(admin_cell):
                        continue
                    user_cell = user_cell.text()
                    admin_cell = admin_cell.text()
                    windows_users_data.append([user_cell, admin_cell])
                    height_windows_users_table -= 16
                except Exception as e:
                    logging.error(f'Error message: {e}')

            table_windows_user_data = Table(windows_users_data,
                                            style=[('OUTLINE', (0, 0), (-1, -1), 0.25, colors.black),
                                                   ('LINEAFTER', (0, 0), (0, -1), 0.25, colors.black),
                                                   ('LINEBELOW', (0, 0), (-1, 0), 0.25, colors.black)], colWidths=250)
            table_windows_user_data.wrapOn(my_canvas, width, height)
            table_windows_user_data.drawOn(my_canvas, 50, height_windows_users_table)

            # Footer
            para_footer.drawOn(my_canvas, 50, 20)
            # Page number
            para_page_number_1 = Paragraph('<font size=6>pagina 2 van 2</font>', style=styles['Normal'])
            para_page_number_1.wrapOn(my_canvas, width, height)
            para_page_number_1.drawOn(my_canvas, width / 2, 5)

            # META Data
            my_canvas.setAuthor(f'{engineer}')
            my_canvas.setTitle(f'Deployment Report - {project}')
            my_canvas.setSubject(f'Device Hostname - {hostname}')
            my_canvas.setCreator('Jeroen Brauns - Heijmans N.V.')
            my_canvas.setProducer('Jeroen Brauns - Heijmans N.V.')
            my_canvas.setKeywords([project, engineer, hostname])

            # Create PDF
            my_canvas.save()

            self.powershell([f'start "{filename}"'])
        except Exception as e:
            logging.error(f'Deployment report failed with message: {e}')

    # Windows
    def open_hostname_help_window(self):
        hostname_window = HostnameWindow()
        hostname_window.exec_()

    def open_info_window(self):
        info_window_ = InfoWindow()
        info_window_.exec_()

    def open_license_window(self):
        license_window_ = LicenceWindow()
        license_window_.exec_()

    def open_logging_window(self):
        logging_window_ = LoggingWindow()
        logging_window_.exec_()

    def open_admin_window(self):
        admin_window_ = AdminWindow()
        admin_window_.exec_()


class HostnameWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(600, 400)
        loadUi(ui_hostname_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))


class InfoWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(ui_info_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        self.setFixedSize(320, 300)
        # Logo
        self.label_info_logo.setText("")
        self.label_info_logo = QLabel(self)
        info_icon = QPixmap(icon_window)
        info_icon = info_icon.scaledToWidth(40)
        self.label_info_logo.setPixmap(info_icon)
        self.label_info_logo.move(140, 10)
        # Labels
        self.label_info_title.setText(f'Windows Deployment Tool v{current_version} <br/> <font size=1>Heijmans N.V.</font>')
        self.label_info_link.setText('<a href="https://github.com/jebr/windows-deployment-tool">GitHub repository</a>')
        self.label_info_link.setOpenExternalLinks(True)
        self.label_info_dev.setText('Developers\nJeroen Brauns / Niels van den Bos')
        self.pushButton_update_check.clicked.connect(website_update)


class LicenceWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(ui_license_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        self.setFixedSize(420, 500)
        # Logo
        self.label_info_logo.setText("")
        self.label_info_logo = QLabel(self)
        info_icon = QPixmap(icon_window)
        info_icon = info_icon.scaledToWidth(40)
        self.label_info_logo.setPixmap(info_icon)
        self.label_info_logo.move(180, 10)
        # Labels
        self.label_info_title.setText(f'Windows Deployment Tool v{current_version}')
        self.label_info_company.setText('Heijmans N.V.')
        self.label_info_link.setText('<a href="https://github.com/jebr/windows-deployment-tool">GitHub repository</a>')
        self.label_info_link.setOpenExternalLinks(True)
        with open(license_file) as file:
            license_text = file.read()
        self.plainTextEdit_license.setPlainText(license_text)
        self.plainTextEdit_license.centerCursor()
        self.plainTextEdit_license.centerOnScroll()


class LoggingWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(ui_logging_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        self.setFixedSize(600, 800)
        # Logo
        self.label_logging_logo.setText("")
        self.label_logging_logo = QLabel(self)
        info_icon = QPixmap(icon_window)
        info_icon = info_icon.scaledToWidth(40)
        self.label_logging_logo.setPixmap(info_icon)
        self.label_logging_logo.move(280, 10)
        # Labels
        self.label_logging_title.setText(f'Windows Deployment Tool v{current_version}')
        self.label_info_company.setText('Heijmans N.V.')
        with open(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log') as file:
            license_text = file.read()
        self.plainTextEdit_logging.setPlainText(license_text)
        self.plainTextEdit_logging.centerCursor()
        self.plainTextEdit_logging.centerOnScroll()
        # Buttons
        self.pushButton_clear_log.clicked.connect(self.clear_wdt_log)
        self.pushButton_export_log.clicked.connect(self.export_wdt_log)
        self.pushButton_delete_log.clicked.connect(self.delete_wdt_log)

    def clear_wdt_log(self):
        with open(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log', 'w'): pass
        self.plainTextEdit_logging.clear()

    def export_wdt_log(self):
        wdt_log = self.plainTextEdit_logging.toPlainText()
        try:
            with open(f'C:\\Users\\{current_user}\\Desktop\\WDT.log', 'w+') as file:
                file.write(wdt_log)
                self.infobox(f'WDT.log is opgeslagen op de locatie: C:\\Users\\{current_user}\\Desktop.')
                try:
                    self.powershell([f'start c:\\users\\{current_user}\\Desktop\\WDT.log'])
                except Exception as e:
                    self.infobox(f'Log kan niet automatisch geopend worden.\nError: {e}')
        except Exception as e:
            self.infobox(f'Log kan niet geexporteerd worden.\nError: {e}')

    def delete_wdt_log(self):
        self.infobox(f'WDT.log kan handmatig verwijderd worden nadat WDT is afgesloten.\n\nLocatie: '
                     f'C:\\Users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log\n\n'
                     f'De verkenner zal geopend worden nadat op OK is geklikt.')
        try:
            self.powershell([f'start C:\\Users\\{current_user}\\AppData\\Local\\Temp\\WDT'])
        except Exception as e:
            self.infobox(f'WDT.log kan niet verwijderd worden.\nError: {e}')


class AdminWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(320, 250)
        loadUi(ui_admin_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        # Enable Administrator button
        self.PushButton_enable_admin.clicked.connect(self.enable_admin_account)

        self.local_admin_enabled = self.powershell(['(Get-LocalUser Administrator).enabled'])
        if eval(self.local_admin_enabled):
            self.checkBox_activate_admin.setChecked(True)
            self.checkBox_activate_admin.setText('Account geactiveerd')
            self.label_activate_check.setText('')
            self.checkBox_activate_admin.setEnabled(False)

    def enable_admin_account(self):
        if not self.lineEdit_password.text():
            self.warningbox('Vul het wachtwoord in')
            return False
        if not self.lineEdit_password_check.text():
            self.warningbox('Herhaal het wachtwoord')
            return False
        if not self.lineEdit_password.text() == self.lineEdit_password_check.text():
            self.warningbox('De ingevoerde wachtwoorden komen niet overeen')
            return False
        try:
            # Change Admin password without activate
            if not self.checkBox_activate_admin.isChecked() and not eval(self.local_admin_enabled):
                self.powershell([f'net user "Administrator" "{self.lineEdit_password.text()}" /add /expires:never /Y'])
                self.infobox(f'Let op!\nHet Administrator account is niet geactiveerd\nHet wachtwoord \"{self.lineEdit_password.text()}\" is ingesteld voor het Adminstrator account')
            # Activate Admin account with password
            elif self.checkBox_activate_admin.isChecked() and not eval(self.local_admin_enabled):
                self.powershell(['Enable-LocalUser Administrator'])
                self.powershell([f'net user "Administrator" "{self.lineEdit_password.text()}" /add /expires:never /Y'])
                self.infobox(f'Administrator account is geactiveerd met het wachtwoord \"{self.lineEdit_password.text()}\"')
            # Change Admin password for activated account
            elif self.checkBox_activate_admin.isChecked() and eval(self.local_admin_enabled):
                self.powershell([f'net user "Administrator" "{self.lineEdit_password.text()}" /add /expires:never /Y'])
                self.infobox(f'Het wachtwoord \"{self.lineEdit_password.text()}\" is ingesteld voor het Administrator account')
        except Exception as e:
            logging.error(f'Add Administrator account or change password failed. Error: {e}')

        # Close Window
        self.close()



def main():
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    # main()
    if is_admin():  # Check admin rights
        main()
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)