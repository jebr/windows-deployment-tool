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
import time
import threading
import urllib3
import webbrowser
from datetime import datetime
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors

from PyQt5.QtCore import QDateTime, QDate, Qt, QThread
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem, QLabel, QScrollArea
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
current_version = float(1.0)

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

# Release page
def website_update():
    webbrowser.open('https://github.com/jebr/windows-deployment-tool/releases')

class MainPage(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        loadUi(resource_path('../resources/ui/main_window.ui'), self)
        self.setFixedSize(900, 760)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))
        self.actionAbout.triggered.connect(self.open_info_window)
        self.actionLicence.triggered.connect(self.open_license_window)
        self.actionLogging.triggered.connect(self.open_logging_window)

        # Controleer systeemtaal
        windll = ctypes.windll.kernel32
        windll.GetUserDefaultUILanguage()
        self.os_language = locale.windows_locale[windll.GetUserDefaultUILanguage()]

        # Controleer windows versie
        self.os_version = platform.platform()

        # Hostname
        self.hostname = os.getenv('COMPUTERNAME')

        # System checks
        self.pushButton_system_check.clicked.connect(self.system_checks_thread)
        self.pushButton_check_secpol.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_secpol.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_check_rdp.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_rdp.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_usb.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_check_windows_updates.clicked.connect(self.open_update)
        self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
        self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))

        # Pre-system checks
        logging.info(f'========{date_time}========')

        if self.check_update_wdt():  # Check for update WDT
            self.infobox_update(f'v{self.new_version} is nu beschikbaar om te installeren.\n Wil je deze nu downloaden?')
            self.statusBar().showMessage(f'Nieuwe versie beschikbaar v{self.new_version}')
            logging.info(f'Initial check: Current software version v{current_version}')
            logging.info(f'Initial check: New version available v{self.new_version}')
        else:
            self.statusBar().showMessage(f'Windows Deployment Tool v{self.new_version}')
            logging.info(f'Initial check: Current software version v{current_version}')

        self.windows7_check()
        self.usb_check_thread()
        threading.Thread(target=self.energy_check, daemon=True).start()  # Check energy settings

        # Hostname
        self.pushButton_info_hostname.clicked.connect(self.open_hostname_help_window)
        self.pushButton_info_hostname.setIcon(QIcon(QPixmap(resource_path('../icons/circle-info.png'))))
        self.pushButton_info_hostname.setToolTip('Klik voor informatie over computernaam')
        self.label_hostname.setText('Huidige computernaam: {}'.format(os.getenv('COMPUTERNAME')))
        self.pushButton_set_hostname.clicked.connect(self.set_hostname)

        # Import users
        self.pushButton_import_csv.clicked.connect(self.load_csv_file)
        self.pushButton_users_add.clicked.connect(self.add_windows_users)
        self.pushButton_clear_users_table.clicked.connect(self.clear_users_table)

        # Security policy
        self.pushButton_sec_policy.clicked.connect(self.import_sec_policy_thread)

        # USB-storage
        self.pushButton_usb_enable.clicked.connect(self.enable_usb_thread)
        self.pushButton_usb_disable.clicked.connect(self.disable_usb_thread)

        # Firewall instellingen
        self.pushButton_firewall_ping.clicked.connect(self.firewall_ping_thread)
        self.pushButton_firewall_discovery.clicked.connect(self.firewall_network_discovery_thread)

        # Remote desktop (RDP)
        self.pushButton_rdp_enable.clicked.connect(self.enable_rdp_thread)

        # Energy settings
        self.pushButton_energy_on.clicked.connect(self.enery_on_thread)
        self.pushButton_energy_lock.clicked.connect(self.enery_lock_thread)
        self.pushButton_energy_default.clicked.connect(self.enery_restore_thread)

        # Restart system
        self.pushButton_restart_system.clicked.connect(self.restart_system)

        # Update button
        self.actioncheck_update_wdt.triggered.connect(self.check_update_wdt_button)

        # Create report button:
        self.pushButton_export_system_settings.clicked.connect(self.create_pdf_report_thread)

        # Set date for report
        datetime = QDateTime.currentDateTime()
        self.dateEdit_date.setDateTime(datetime)

        # Set counter for started threads
        self.counter_threads = 0

    # Button to check on updates
    def check_update_wdt_button(self):
        if self.check_update_wdt():
            self.infobox_update(
                f'v{self.new_version} is nu beschikbaar om te installeren.\n Wil je deze nu downloaden?')
            self.statusBar().showMessage(f'Nieuwe versie beschikbaar v{self.new_version}')
            logging.info(f'Update button: Current software version v{current_version}')
            logging.info(f'Update button: New version available v{self.new_version}')
        else:
            self.infobox(f'Je maakt momenteel gebruik van de nieuwste versie (v{current_version})')
            logging.info(f'Update button: Current software version v{current_version}')

    # WDT update check
    def check_update_wdt(self):
        try:
            timeout = urllib3.Timeout(connect=2.0, read=7.0)
            http = urllib3.PoolManager(timeout=timeout)
            response = http.request('GET',
                                    'https://raw.githubusercontent.com/jebr/windows-deployment-tool/master/version.txt')
            data = response.data.decode('utf-8')

            self.new_version = float(data)

            if current_version < self.new_version:
                # logging.info('Current software version: v{}'.format(current_version))
                # logging.info('New software version available v{}'.format(new_version))
                # logging.info('https://github.com/jebr/windows-deployment-tool/releases')
                # self.infobox_update(f'v{self.new_version} is nu beschikbaar om te installeren.\n Wil je deze nu downloaden?')
                # self.statusBar().showMessage(f'Nieuwe versie beschikbaar v{self.new_version}')
                return True
            else:
                # logging.info('Current software version: v{}'.format(current_version))
                # logging.info('Latest release: v{}'.format(new_version))
                # logging.info('Software up-to-date')
                # self.statusBar().showMessage(f'Windows Deployment Tool v{self.new_version}')
                # self.infobox(f'Je maakt momenteel gebruik van de nieuwste versie (v{current_version})')
                return False

        except urllib3.exceptions.MaxRetryError:
            logging.error('No internet connection, max retry error')
        except urllib3.exceptions.ResponseError:
            logging.error('No internet connection, no response error')

    # System checks
    def system_checks(self):
        self.counter_threads = 0
        self.pushButton_system_check.setEnabled(False)
        threading.Thread(target=self.windows_chars, daemon=True).start()
        threading.Thread(target=self.secpol_check, daemon=True).start()
        threading.Thread(target=self.rdp_check, daemon=True).start()
        threading.Thread(target=self.fw_icmp_check, daemon=True).start()
        threading.Thread(target=self.fw_discovery_check, daemon=True).start()
        # threading.Thread(target=self.energy_check, daemon=True).start() # WIP controleren in VM of deze check nog nodig is
        threading.Thread(target=self.get_users, daemon=True).start()
        while True:
            if self.counter_threads == 6:  # Verhogen als er meer threads in deze functie geplaatst worden
                break
            time.sleep(0.05)
        self.pushButton_export_system_settings.setEnabled(True)
        self.pushButton_system_check.setEnabled(True)

    def system_checks_thread(self):
        thread = threading.Thread(target=self.system_checks, daemon=True)
        thread.start()

    def windows7_check(self):
        os_version = platform.platform()
        if "Windows-7" in os_version:
            self.warningbox('Windows 7 wordt niet meer ondersteund\nDe applicatie zal afgesloten worden')
            logging.error(f'Initial check: Windows 7 is not supported')
            sys.exit()

    def energy_check(self):
        energy_on_scheme = '00000000-0000-0000-0000-000000000000'
        energy_lock_scheme = '39ff2e23-e11c-4fc3-ab0f-da25fadb8a89'

        active_scheme = subprocess.check_output(['powershell.exe', 'powercfg /getactivescheme'])
        active_scheme = active_scheme.decode('utf-8')

        if energy_on_scheme in active_scheme:
            self.label_energie_settings.setText('Altijd aan')
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('Initial check: Energy plan - Always on')
        elif energy_lock_scheme in active_scheme:
            self.label_energie_settings.setText('Automatisch vergrendelen')
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('Initial check: Energy plan - Lock automatically')
        else:
            self.label_energie_settings.setText('Standaard energieplan')
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('Initial check: Energy plan - Default')
        self.counter_threads += 1

    def secpol_check(self):
        if os.path.exists('c:\\windows\\system32\secpol_new.inf'):
            self.pushButton_check_secpol.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_secpol.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('System check: Security policy applied ')
            return True
        else:
            logging.info('System check: Security policy not applied')
        self.counter_threads += 1

    def rdp_check(self):
        self.rdp_register_path = 'Registry::"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"'
        self.rdp_reg_dword = "fDenyTSConnections"
        # Controleer de waarde van het register
        self.check_rdp = str(subprocess.check_output(['powershell.exe', 'Get-ItemProperty -Path {} -Name {}'.format(self.rdp_register_path, self.rdp_reg_dword)]))
        if "0" in self.check_rdp:
            self.pushButton_check_rdp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_rdp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('System check: RDP activated')
            return True
        else:
            logging.info('System check: RDP not activated')
        self.counter_threads += 1

    def fw_icmp_check(self):
        icmp_rule_nl = str('Get-NetFirewallRule -DisplayName \"Bestands- en printerdeling '
                           '(Echoaanvraag - ICMPv4-In)\" | select DisplayName, Enabled')
        icmp_rule_en = str('Get-NetFirewallRule -DisplayName \"File and Printer Sharing '
                           '(Echo Request - ICMPv4-In)\" | select DisplayName, Enabled')
        if "nl" in self.os_language:
            try:
                check_nl = str(subprocess.check_output(['powershell.exe', icmp_rule_nl]))
                if "True" in check_nl:
                    self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    self.pushButton_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    logging.info('System check: Firewall ICMP allowed')
                    return True
                else:
                    logging.info('System check: Firewall ICMP blocked')
            except Exception as e:
                logging.info(f'System check: Firewall ICMP check failed with message: {e}')
        else:
            try:
                check_en = str(subprocess.check_output(['powershell.exe', icmp_rule_en]))
                if "True" in check_en:
                    self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    self.pushButton_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    logging.info('System check: Firewall ICMP allowed')
                else:
                    logging.info('System check: Firewall ICMP blocked')
            except Exception as e:
                logging.info(f'System check: Firewall ICMP check failed with message {e}')
        self.counter_threads += 1

    def fw_discovery_check(self):
        # Netwerk detecteren (NB-Datagram-In)
        # Network Discovery (NB-Datagram-In)
        if "nl" in self.os_language:
            try:
                check_en = subprocess.check_output(['powershell.exe', 'Get-NetFirewallRule -DisplayName '
                                                                      '"Netwerk detecteren (NB-Datagram-In)"  | '
                                                                      'select DisplayName, Enabled'])
                check_en = check_en.decode('utf-8')
                check_true = check_en.count("True")
                if check_true == 3:
                    self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/'
                                                                                           'circle-check.png'))))
                    self.pushButton_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    logging.info('System check: Firewall discovery allowed')
                    return True
                else:
                    logging.info('System check: Firewall discovery blocked')
            except Exception as e:
                logging.info(f'System check: Firewall discovery check failed with message: {e}')
        else:
            try:
                check_en = subprocess.check_output(['powershell.exe', 'Get-NetFirewallRule -DisplayName '
                                                           '"Network Discovery (NB-Datagram-In)"  | '
                                                           'select DisplayName, Enabled'])
                check_en = check_en.decode('utf-8')
                check_true = check_en.count("True")
                if check_true == 3:
                    self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/'
                                                                                           'circle-check.png'))))
                    self.pushButton_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    logging.info('System check: Firewall discovery allowed')
                else:
                    logging.info('System check: Firewall discovery blocked')
            except Exception as e:
                logging.info(f'System check: Firewall discovery check failed with message: {e}')
        self.counter_threads += 1

    def windows_chars(self):
        w_version = subprocess.check_output(['powershell.exe', '(Get-WmiObject -class Win32_OperatingSystem).Caption'])
        w_version = w_version.decode('utf-8')
        self.label_windows_version.setText(w_version.rstrip())
        logging.info(f'System check: Windows version - {w_version.rstrip()}')

        if 'nl' in self.os_language:
            self.label_windows_lang.setText('Nederlands')
            logging.info(f'System check: Language - Dutch')
        elif 'en' in self.os_language:
            self.label_windows_lang.setText('Engels')
            logging.info(f'System check: Language - English')
        else:
            self.label_windows_lang.setText(self.os_language)
            logging.info(f'System check: Language {self.os_language}')

        # Domain / Workgroup check
        w_domain_workgroup = subprocess.check_output(['powershell.exe', '(Get-WmiObject Win32_ComputerSystem).domain'])
        w_domain_workgroup = w_domain_workgroup.decode('utf-8')
        self.label_domain_workgroup.setText(f'{w_domain_workgroup.rstrip()}')
        logging.info(f'System check: Workgroup / Domain - {w_domain_workgroup.rstrip()}')

        # Get Hostname
        windows_hostname = os.getenv('COMPUTERNAME')
        self.label_windows_hostname.setText(windows_hostname)
        logging.info(f'System check: Hostname - {windows_hostname}')

        # Get Manufacturer and model
        manufacturer = subprocess.check_output(['powershell.exe', '(get-wmiobject Win32_ComputerSystem).manufacturer'])
        manufacturer = manufacturer.decode('utf-8')
        model = subprocess.check_output(['powershell.exe', '(get-wmiobject Win32_ComputerSystem).model'])
        model = model.decode('utf-8')
        self.label_manufacturer_model.setText(f'{manufacturer.rstrip()} / {model.rstrip()}')
        logging.info(f'System check: Manufacturer / Model - {manufacturer.rstrip()} / {model.rstrip()}')

        # Get PC Type
        type_number = subprocess.check_output(['powershell.exe', '(get-wmiobject Win32_ComputerSystem).PCSystemTypeEx'])
        type_number = int(type_number.decode('utf-8').rstrip())
        if type_number == 1:
            self.label_type.setText('Desktop')
            logging.info('System check: Computer type - Desktop')
        elif type_number == 2:
            self.label_type.setText('Mobile / Laptop')
            logging.info('System check: Computer type - Mobile / Laptop')
        elif type_number == 3:
            self.label.type.setText('Workstation')
            logging.info('System check: Computer type - Workstation')
        elif type_number == 4:
            self.label_type.setText('Enterprise Server')
            logging.info('System check: Computer type - Server')
        elif type_number == 5:
            self.label_type.setText('Small Office Server (SOHO)')
            logging.info('System check: Computer type - Small Office Server')
        elif type_number == 6:
            self.label_type.setText('Appliance PC')
            logging.info('System check: Computer type - Appliance PC')
        elif type_number == 7:
            self.label_type.setText('Performance Server')
            logging.info('System check: Computer type - Performance Server')
        elif type_number == 8:
            self.label_type.setText('Maximum')
            logging.info('System check: Computer type - Maximum')
        else:
            self.label_type('Onbekend product type')
            logging.info('System check: Computer type - Unknown')

        # Calculate RAM
        bytes_number = subprocess.check_output(
            ['powershell.exe', '(get-wmiobject Win32_ComputerSystem).totalphysicalmemory'])
        bytes_number = int(bytes_number.decode('utf-8'))
        gb_number = bytes_number / (1024 ** 3)
        gb_number = round(gb_number)
        self.label_physicalmemory.setText(f'{gb_number} GB')
        logging.info(f'System check: RAM {gb_number} GB')

        # Get Processor info
        processor_name = subprocess.check_output(['powershell.exe', '(get-wmiobject Win32_Processor).name']).decode('utf-8')
        self.label_processor.setText(processor_name.rstrip())
        self.label_processor.setToolTip(processor_name.rstrip())
        logging.info(f'System check: Processor - {processor_name.rstrip()}')
        processor_cores = subprocess.check_output(['powershell.exe', '(get-wmiobject Win32_Processor).NumberOfCores']).decode('utf-8')
        processor_logicalprocessors = subprocess.check_output(['powershell.exe', '(get-wmiobject Win32_Processor).NumberOfLogicalProcessors']).decode('utf-8')
        self.label_cores.setText(f'{processor_cores.rstrip()} cores / {processor_logicalprocessors.rstrip()} logical processors')
        logging.info(f'System check: Processor cores - {processor_cores.rstrip()} cores / {processor_logicalprocessors.rstrip()} logical processors')

        # Get Windows Build and Version
        w_release_id = subprocess.check_output(
            ['powershell.exe', '(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseID'])
        w_release_id = w_release_id.decode('utf-8')
        w_release_version = subprocess.check_output(
            ['powershell.exe', '(Get-WmiObject Win32_OperatingSystem).Version'])
        w_release_version = w_release_version.decode('utf-8')
        self.label_windows_build.setText(f'{w_release_version.rstrip()} / {w_release_id.rstrip()}')
        logging.info(f'System check: Windows build - {w_release_version.rstrip()} / {w_release_id.rstrip()}')

        self.counter_threads += 1

    def open_update(self):
        try:
            subprocess.check_call(['powershell.exe', 'C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate'])
        except Exception as e:
            logging.info('Openen Windows update is mislukt.')

    def get_users(self):
        w_users = subprocess.check_output(['powershell.exe', 'Get-LocalUser | select name, enabled'])
        w_users = w_users.decode('utf-8')
        w_users_output = w_users.splitlines()
        w_group_admin = subprocess.check_output(['powershell.exe', 'net localgroup administrators'])
        w_group_admin = w_group_admin.decode('utf-8')
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

    # Firewall
    def firewall_ping(self):
        if "nl" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe',
                                       'Set-NetFirewallRule -DisplayName \"Bestands- en '
                                       'printerdeling (Echoaanvraag - ICMPv4-In)\" -Profile Any -Enabled True'])
                self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                logging.info('Firewall ICMP activated')
            except Exception as e:
                logging.error(f'Firewall ICMP failed with message: {e}')
        else:
            try:
                subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"File and Printer Sharing '
                                                         '(Echo Request - ICMPv4-In)\" -Profile Any -Enabled True'])
                self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                logging.info('Firewall ICMP activated')
            except Exception as e:
                logging.error(f'Firewall ICMP failed with message: {e}')
            
    def firewall_ping_thread(self):
        thread = threading.Thread(target=self.firewall_ping, daemon=True)
        thread.start()

    def firewall_network_discovery(self):
        if "nl" in self.os_language:
            try:
                subprocess.check_call(['powershell.exe', 'netsh advfirewall firewall '
                                                         'set rule group=”Network Discovery” new enable=Yes'])
                self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                logging.info('Firewall Discovery activated')
            except Exception as e:
                logging.error(f'Firewall Discovery failed with message: {e}')
        else:
            try:
                subprocess.check_call(['powershell.exe', 'netsh advfirewall firewall '
                                                         'set rule group=”Network Discovery” new enable=Yes'])
                self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                logging.info('Firewall Discovery activated')
            except Exception as e:
                logging.error(f'Firewall Discovery failed with message: {e}')
    
    def firewall_network_discovery_thread(self):
        thread = threading.Thread(target=self.firewall_network_discovery, daemon=True)
        thread.start()

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
        self.hostname = new_hostname
        if not self.checkout_hostname(new_hostname):
            self.criticalbox('Ongeldige computernaam, zie info button')
            return
        try:
            subprocess.check_call(['powershell.exe', f'Rename-Computer -NewName {new_hostname}'])
            self.label_hostname_new.setText(f'Nieuwe computernaam: {new_hostname}')
            self.lineEdit_hostname.clear()
            logging.info(f'Hostname changed to: {new_hostname}')
        except Exception as e:
            logging.error(f'Hostname change failed with message: {e}')

    # Security
    def import_sec_policy(self):
        secpol_new = resource_path('\\src\\resources\\security\\secpol_new.inf')
        if not os.path.exists(secpol_new):
            self.criticalbox('Kan secpol_new.inf niet vinden \nFunctie kan niet uitgevoerd worden!')
            logging.info('secpol_new.inf is not found on the system. Execution of security policy failed')
        else:
            current_user_Desktop = 'c:\\users\\{}\\desktop'.format(getpass.getuser())
            program_cwd = os.getcwd()

            # Backup maken van de huidige security policy
            try:
                os.chdir("c:\\windows\\system32")
                subprocess.check_call(['powershell.exe', 'c:\\windows\\system32\\secedit '
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
                    subprocess.check_call(['powershell.exe', 'c:\\windows\\system32\\secedit /configure '
                                                             '/db c:\\windows\\system32\\defltbase.sdb /cfg {} '
                                                             '/overwrite /log c:\\windows\\system32\\secpol_import.log '
                                                             '/quiet'.format(secpol_new)])
                    logging.info('Import security policy succesful')
                    try:
                        subprocess.check_call(['powershell.exe', 'echo y | gpupdate /force /wait:0'])
                        self.pushButton_check_secpol.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
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

    def import_sec_policy_thread(self):
        thread = threading.Thread(target=self.import_sec_policy, daemon=True)
        thread.start()

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
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_usb.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            logging.info('Initial check: USB-storage Enabled')
        # Als de waarde 4 is de USB gedeactiveerd
        elif "4" in self.check_usb:
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_usb.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('Initial check: USB-storage Disabled')
            return True
        else:
            logging.error('USB-storage check failed. Value of register doesn\'t match number 3 or 4.')

    def usb_check_thread(self):
        thread = threading.Thread(target=self.usb_check, daemon=True)
        thread.start()

    def enable_usb(self):
        try:
            subprocess.check_call(['powershell.exe', 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet'
                                                     '\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f'])
            self.pushButton_usb_enable.setDisabled(True)
            self.pushButton_usb_disable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_usb.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            logging.info('USB-storage enabled')
        except Exception as e:
            logging.error(f'Enable USB-storage failed with message: {e}')

    def enable_usb_thread(self):
        thread = threading.Thread(target=self.enable_usb, daemon=True)
        thread.start()

    def disable_usb(self):
        try:
            subprocess.check_call(['powershell.exe', 'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet'
                                                     '\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f'])
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_usb.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            logging.info('USB-storage disabled')
        except Exception as e:
            self.criticalbox(f'Disable USB-storage failed with message: {e}')

    def disable_usb_thread(self):
        thread = threading.Thread(target=self.disable_usb, daemon=True)
        thread.start()

    # Wimndows settings
    def enable_rdp(self):
        if self.rdp_check():
            logging.info('RDP is al geactiveerd op deze computer')
            return
        else:
            if "nl" in self.os_language:
                try:
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                             'Gebruikersmodus (TCP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                             'Gebruikersmodus (UDP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                                             'Schaduw (TCP-In)\" -Profile Any -Enabled True'])
                    logging.info('Firewall instellingen voor RDP zijn geactiveerd')
                except Exception as e:
                    logging.error(f'Firewall settings RDP failed with message: {e}')
            elif "en" in self.os_language:
                try:
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                             'User Mode (TCP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                             'User Mode (UDP-In)\" -Profile Any -Enabled True'])
                    subprocess.check_call(['powershell.exe', 'Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                                             'Shadow (TCP-In)\" -Profile Any -Enabled True'])
                    logging.info('Firewall instellingen voor RDP zijn geactiveerd')
                except Exception as e:
                    logging.error(f'Firewall settings RDP failed with message: {e}')
            try:
                subprocess.check_call(['powershell.exe', 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'])
                subprocess.check_call(['powershell.exe', 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\" /v SecurityLayer /t REG_DWORD /d 0 /f'])
                subprocess.check_call(['powershell.exe', 'reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f'])
                logging.info('De register wijzigingen voor RDP zijn geslaagd')
                self.pushButton_check_rdp.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            except Exception as e:
                logging.error(f'Register settings for RDP failed with message: {e}')

    def enable_rdp_thread(self):
        thread = threading.Thread(target=self.enable_rdp, daemon=True)
        thread.start()

    # Energy Settings
    def energy_on(self):
        energy_config = resource_path('../resources/energy/energy-full.pow')
        energy_on_scheme = '00000000-0000-0000-0000-000000000000'

        scheme_list = subprocess.check_output(['powershell.exe', 'powercfg /list'])
        scheme_list = scheme_list.decode('utf-8')

        active_scheme = subprocess.check_output(['powershell.exe', 'powercfg /getactivescheme'])
        active_scheme = active_scheme.decode('utf-8')

        # Check active scheme
        if energy_on_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            return

        if energy_on_scheme in scheme_list:
            try:
                subprocess.check_call(['powershell.exe', 'powercfg /delete {}'.format(energy_on_scheme)])
                try:
                    subprocess.check_call(['powershell.exe', 'powercfg -import {} {}'
                                          .format(energy_config, energy_on_scheme)])
                    subprocess.check_call(['powershell.exe', 'powercfg -setactive {}'.format(energy_on_scheme)])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    self.pushButton_check_energy_default.setIcon(
                        QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                    logging.info('Enery plan: always on activated')
                except Exception as e:
                    logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                subprocess.check_call(['powershell.exe', 'powercfg -import {} {}'
                                      .format(energy_config, energy_on_scheme)])
                subprocess.check_call(['powershell.exe', 'powercfg -setactive {}'.format(energy_on_scheme)])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                logging.info('Enery plan: always on activated')
            except Exception as e:
                logging.error(f'Import energy plan failed with message {e}')
                
    def enery_on_thread(self):
        thread = threading.Thread(target=self.energy_on, daemon=True)
        thread.start()

    def energy_lock(self):
        energy_config = resource_path('../resources/energy/energy-auto-lock.pow')
        energy_lock_scheme = '39ff2e23-e11c-4fc3-ab0f-da25fadb8a89'

        scheme_list = subprocess.check_output(['powershell.exe', 'powercfg /list'])
        scheme_list = scheme_list.decode('utf-8')

        active_scheme = subprocess.check_output(['powershell.exe', 'powercfg /getactivescheme'])
        active_scheme = active_scheme.decode('utf-8')

        # Check active scheme
        if energy_lock_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            return

        if energy_lock_scheme in scheme_list:
            try:
                subprocess.check_call(['powershell.exe', 'powercfg /delete {}'.format(energy_lock_scheme)])
                try:
                    subprocess.check_call(['powershell.exe', 'powercfg -import {} {}'
                                          .format(energy_config, energy_lock_scheme)])
                    subprocess.check_call(['powershell.exe', 'powercfg -setactive {}'.format(energy_lock_scheme)])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                    self.pushButton_check_energy_default.setIcon(
                        QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                    self.pushButton_check_energy_lock.setIcon(
                        QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    logging.info('Enery plan: Auto lock activated')
                except Exception as e:
                    logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                subprocess.check_call(['powershell.exe', 'powercfg -import {} {}'
                                      .format(energy_config, energy_lock_scheme)])
                subprocess.check_call(['powershell.exe', 'powercfg -setactive {}'.format(energy_lock_scheme)])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                logging.info('Enery plan: Auto lock activated')
            except Exception as e:
                logging.error(f'Import energy plan failed with message {e}')

    def enery_lock_thread(self):
        thread = threading.Thread(target=self.energy_lock, daemon=True)
        thread.start()

    def energy_restore(self):
        energy_config = resource_path('../resources/energy/energy-default.pow')
        energy_default_scheme = '381b4222-f694-41f0-9685-ff5bb260df2e'

        scheme_list = subprocess.check_output(['powershell.exe', 'powercfg /list'])
        scheme_list = scheme_list.decode('utf-8')

        active_scheme = subprocess.check_output(['powershell.exe', 'powercfg /getactivescheme'])
        active_scheme = active_scheme.decode('utf-8')

        # Check active scheme
        if energy_default_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
            return

        if energy_default_scheme in scheme_list:
            try:
                subprocess.check_call(['powershell.exe', 'powercfg /delete {}'.format(energy_default_scheme)])
                try:
                    subprocess.check_call(['powershell.exe', 'powercfg -import {} {}'
                                          .format(energy_config, energy_default_scheme)])
                    subprocess.check_call(['powershell.exe', 'powercfg -setactive {}'.format(energy_default_scheme)])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                    self.pushButton_check_energy_default.setIcon(
                        QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                    logging.info('Enery plan: Default activated')
                except Exception as e:
                    logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                subprocess.check_call(['powershell.exe', 'powercfg -import {} {}'
                                      .format(energy_config, energy_default_scheme)])
                subprocess.check_call(['powershell.exe', 'powercfg -setactive {}'.format(energy_default_scheme)])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(resource_path('../icons/circle-check.png'))))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(resource_path('../icons/transparent.png'))))
                logging.info('Enery plan: Default activated')
            except Exception as e:
                logging.error(f'Import energy plan failed with message {e}')
    
    def enery_restore_thread(self):
        thread = threading.Thread(target=self.energy_restore, daemon=True)
        thread.start()
    
    # Restart system
    def restart_system(self):
        try:
            subprocess.check_call(['powershell.exe', 'shutdown -r -t 10'])
            self.infobox('Het systeeem zal over 10 seconden herstarten')
        except Exception as e:
            self.warningbox('Door een onbekende fout kan het systeem niet herstart worden')
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
    def get_local_users(self):
        # w_users_full = subprocess.check_output(['powershell.exe', 'Get-LocalUser | select name, enabled, description'])
        w_users = subprocess.check_output(['powershell.exe', '(Get-LocalUser).name']).decode('utf-8').splitlines()
        w_users_enabled = subprocess.check_output(['powershell.exe', '(Get-LocalUser).enabled']).decode('utf-8').splitlines()
        w_users_desc = subprocess.check_output(['powershell.exe', '(Get-LocalUser).description']).decode('utf-8').splitlines()
        w_users_fullname = subprocess.check_output(['powershell.exe', '(get-wmiobject -class Win32_USeraccount).fullname']).decode('utf-8').splitlines()
        w_group_admin = subprocess.check_output(['powershell.exe', 'net localgroup administrators'])
        w_group_admin = w_group_admin.decode('utf-8')
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
        w_users = subprocess.check_output(['powershell.exe', '(Get-LocalUser).name']).decode('utf-8').splitlines()
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
                subprocess.check_call(['powershell.exe', f'net user "{user}" "{password}" /add /active:yes '
                                                         f'/fullname:"{fullname}" /comment:"{desc}" /expires:never /Y'])
                subprocess.check_call(['powershell.exe', f'wmic useraccount where "name=\'{user}\'" set PasswordExpires=False '])
                # subprocess.check_call(['powershell.exe', f'$password = {password} -AsSecureString && New-LocalUser "{user}" -Password $password -Fullname {fullname} -Description {desc}'])
                self.tableWidget_add_users.setItem(i, 0, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 1, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 2, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 3, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 4, QTableWidgetItem(''))
                if admin == True:
                    try:
                        subprocess.check_call(['powershell.exe', f'Add-LocalGroupMember -Group "Administrators" -Member {user}'])
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
        prohobited = '\\/:*?\"<>| ,@[];=+'
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
            self.warningbox('Vul het veld Project in')
        if not self.lineEdit_engineer.text():
            self.warningbox('Vul het veld Medewerker in')
        else:
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
                my_canvas.drawImage('../icons/heijmans-logo.jpg', 400, 770, 156.35, 39.6)

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
                my_canvas.drawImage('../icons/heijmans-logo.jpg', 400, 770, 156.35, 39.6)
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

                secpol_enabled = 'Ja' if self.secpol_check() else 'Nee'
                usb_blocked = 'Ja' if self.usb_check() else 'Nee'
                rdp_enabled = 'Ja' if self.rdp_check() else 'Nee'
                icmp_enabled = 'Ja' if self.fw_icmp_check() else 'Nee'
                discovery_enabled = 'Ja' if self.fw_discovery_check() else 'Nee'

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

                subprocess.check_call(['powershell.exe', f'start "{filename}"'])
            except Exception as e:
                logging.error(f'Deployment report failed with message: {e}')

    def create_pdf_report_thread(self):
        thread = threading.Thread(target=self.create_pdf_report, daemon=True)
        thread.start()

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

    def infobox_update(self, message):
        title = f'Windows Deployment Tool v{current_version}'
        buttonReply = QMessageBox.information(self, title, message, QMessageBox.Yes, QMessageBox.No)
        if buttonReply == QMessageBox.Yes:
            webbrowser.open('https://github.com/jebr/windows-deployment-tool/releases')

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


def powershell(command):
    return subprocess.check_call(['powershell.exe', command])


class HostnameWindow(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(600, 400)
        loadUi(resource_path('../resources/ui/hostname_help_dialog.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))


class InfoWindow(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(resource_path('../resources/ui/info_dialog.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))
        self.setFixedSize(320, 300)
        # Logo
        self.label_info_logo.setText("")
        self.label_info_logo = QLabel(self)
        info_icon = QPixmap(resource_path('../icons/wdt.ico'))
        info_icon = info_icon.scaledToWidth(40)
        self.label_info_logo.setPixmap(info_icon)
        self.label_info_logo.move(140, 10)
        # Labels
        self.label_info_title.setText(f'Windows Deployment Tool v{current_version}')
        self.label_info_link.setText('<a href="https://github.com/jebr/windows-deployment-tool">GitHub repository</a>')
        self.label_info_link.setOpenExternalLinks(True)
        self.label_info_dev.setText('Developers\nJeroen Brauns / Niels van den Bos')
        self.pushButton_update_check.clicked.connect(website_update)


class LicenceWindow(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(resource_path('../resources/ui/license_dialog.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))
        self.setFixedSize(420, 500)
        # Logo
        self.label_info_logo.setText("")
        self.label_info_logo = QLabel(self)
        info_icon = QPixmap(resource_path('../icons/wdt.ico'))
        info_icon = info_icon.scaledToWidth(40)
        self.label_info_logo.setPixmap(info_icon)
        self.label_info_logo.move(180, 10)
        # Labels
        self.label_info_title.setText(f'Windows Deployment Tool v{current_version}')
        self.label_info_link.setText('<a href="https://github.com/jebr/windows-deployment-tool">GitHub repository</a>')
        self.label_info_link.setOpenExternalLinks(True)
        with open('../../LICENSE') as file:
            license_text = file.read()
        self.plainTextEdit_license.setPlainText(license_text)
        self.plainTextEdit_license.centerCursor()
        self.plainTextEdit_license.centerOnScroll()


class LoggingWindow(QDialog):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        loadUi(resource_path('../resources/ui/wdt_logging_dialog.ui'), self)
        self.setWindowIcon(QtGui.QIcon(resource_path('../icons/wdt.ico')))
        self.setFixedSize(600, 800)
        # Logo
        self.label_logging_logo.setText("")
        self.label_logging_logo = QLabel(self)
        info_icon = QPixmap(resource_path('../icons/wdt.ico'))
        info_icon = info_icon.scaledToWidth(40)
        self.label_logging_logo.setPixmap(info_icon)
        self.label_logging_logo.move(260, 10)
        # Labels
        self.label_logging_title.setText(f'Windows Deployment Tool v{current_version}')
        with open(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log') as file:
            license_text = file.read()
        self.plainTextEdit_logging.setPlainText(license_text)
        self.plainTextEdit_logging.centerCursor()
        self.plainTextEdit_logging.centerOnScroll()
        # Buttons
        self.pushButton_clear_log.clicked.connect(self.clear_wdt_log)
        self.pushButton_export_log.clicked.connect(self.export_wdt_log)
        self.pushButton_delete_log.clicked.connect(self.delete_wdt_log)

    def infobox(self, message):
        buttonReply = QMessageBox.information(self, 'Info', message, QMessageBox.Ok)

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
                    subprocess.check_call(['powershell.exe', f'start c:\\users\\{current_user}\\Desktop\\WDT.log'])
                except Exception as e:
                    self.infobox(f'Log kan niet automatisch geopend worden.\nError: {e}')
        except Exception as e:
            self.infobox(f'Log kan niet geexporteerd worden.\nError: {e}')

    def delete_wdt_log(self):
        self.infobox(f'WDT.log kan handmatig verwijderd worden nadat WDT is afgesloten.\n\nLocatie: '
                     f'C:\\Users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log\n\n'
                     f'De verkenner zal geopend worden nadat op OK is geklikt.')
        try:
            subprocess.check_call(['powershell.exe', f'start C:\\Users\\{current_user}\\AppData\\Local\\Temp\\WDT'])
        except Exception as e:
            self.infobox(f'WDT.log kan niet verwijderd worden.\nError: {e}')


def main():
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    if is_admin():  # Check admin rights
        main()
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)