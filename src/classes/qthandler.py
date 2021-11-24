import ctypes
import locale
import os
import platform
import shutil
import subprocess
import logging
import csv
import webbrowser
from datetime import datetime, time

import requests
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, Table
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from PyQt5.QtCore import QDateTime
from PyQt5.QtGui import QPixmap, QIcon
from PyQt5.QtWidgets import QDialog, QFileDialog, QMessageBox, \
    QTableWidgetItem, QLabel
from PyQt5.uic import loadUi
from PyQt5 import QtWidgets, QtGui, QtCore

from wdt_table_users import BaseTable
import handler as handler
from classes.basics.base_functions import thread, powershell
from classes.app_settings.app_settings import *
from classes.app_functions.app_functions import *
from qt_helpers import *



class BaseWindow:


    def checkout_password(self, password, sam_account_name: str, display_name: str) -> bool:
        """Password requirements based on
        https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
        """
        self.password_fault = ''
        if sam_account_name.lower() in password.lower() and len(sam_account_name) > 3:
            self.password_fault = 'De gebruikersnaam mag niet voorkomen in het wachtwoord'
            return False

        splits = ',. \t_+/\\$'
        for split in splits:
            splitted_items = display_name.split(split)
            for elem in splitted_items:
                if len(elem) < 3:
                    continue
                if elem in password:
                    self.password_fault = 'De volledige naam mag niet voorkomen in het wachtwoord'
                    return False

        if display_name.lower() in password.lower():
            self.password_fault = 'De volledige naam mag niet voorkomen in het wachtwoord'
            return False

        if len(password) < 8:
            self.password_fault = 'Het wachtwoord is te kort\ngebruik minimaal 8 karakters.'
            return False

        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        alphabet_up = alphabet.upper()
        special = '~!@#$%^&*_-+=`|\\(){}[]:;"`\'<>,.?/'
        number = '1234567890'

        categories_in_password = 0
        for category in [alphabet, alphabet_up, special, number]:
            for char in category:
                if char in password:
                    categories_in_password += 1
                    break
        if categories_in_password < 3:
            self.password_fault = 'Het wachtwoord niet complex genoeg.\nMaak gebruik van tekens, letters en cijfers'
            return False

        return True


class MainPage(QtWidgets.QMainWindow, BaseWindow, MessageBoxes):
    def __init__(self):
        super().__init__()
        loadUi(ui_main_window, self)
        self.setFixedSize(900, 850)
        self.setWindowIcon(QtGui.QIcon(icon_window))
        self.actionAbout.triggered.connect(self.open_info_window)
        self.actionLicence.triggered.connect(self.open_license_window)
        self.actionLogging.triggered.connect(self.open_logging_window)
        self.actionAdministrator_Account.triggered.connect(self.open_admin_window)
        self.actionVersion.setText(f'Versie v{handler.wdt_current_version()}')
        self.action_documentaion.triggered.connect(handler.open_documentation_website)

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
        self.pushButton_check_support_info.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_add_oem_info_check.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_ntp_server.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_ntp_server.setIcon(QIcon(QPixmap(icon_transparant_image)))
        self.pushButton_check_ntp_client.setIcon(QIcon(QPixmap(icon_transparant_image)))

        # New functionality setup
        self.label_windows_lang.setText(handler.config.get_application_config_subject_item("system_information", "windows_language"))
        self.label_windows_lang.setToolTip(handler.config.get_application_config_subject_item("system_information", "windows_language"))
        self.label_windows_version.setText(handler.config.get_application_config_subject_item("system_information", "os_version"))
        self.label_windows_version.setToolTip(handler.config.get_application_config_subject_item("system_information", "os_version"))
        self.label_domain_workgroup.setText(handler.config.get_application_config_subject_item("system_information", "domain_workgroup"))
        self.label_domain_workgroup.setToolTip(handler.config.get_application_config_subject_item("system_information", "domain_workgroup"))
        self.label_windows_hostname.setText(handler.config.get_application_config_subject_item("system_information", "computername"))
        self.label_windows_hostname.setToolTip(handler.config.get_application_config_subject_item("system_information", "computername"))
        self.label_manufacturer_model.setText(f'{handler.config.get_application_config_subject_item("system_information", "pc_manufacturer")} / {handler.config.get_application_config_subject_item("system_information", "pc_model")}')
        self.label_manufacturer_model.setToolTip(f'{handler.config.get_application_config_subject_item("system_information", "pc_manufacturer")} / {handler.config.get_application_config_subject_item("system_information", "pc_model")}')
        self.label_type.setText(handler.config.get_application_config_subject_item("system_information", "pc_type"))
        self.label_type.setToolTip(handler.config.get_application_config_subject_item("system_information", "pc_type"))
        self.label_physicalmemory.setText(handler.config.get_application_config_subject_item("system_information", "pc_ram"))
        self.label_physicalmemory.setToolTip(handler.config.get_application_config_subject_item("system_information", "pc_ram"))
        self.label_processor.setText(handler.config.get_application_config_subject_item("system_information", "pc_processor"))
        self.label_processor.setToolTip(handler.config.get_application_config_subject_item("system_information", "pc_processor"))
        self.label_cores.setText(f'{handler.config.get_application_config_subject_item("system_information", "pc_processor_cores")} cores / {handler.config.get_application_config_subject_item("system_information", "pc_processor_logical_processors")} logical processors')
        self.label_cores.setToolTip(f'{handler.config.get_application_config_subject_item("system_information", "pc_processor_cores")} cores / {handler.config.get_application_config_subject_item("system_information", "pc_processor_logical_processors")} logical processors')
        self.label_windows_build.setText(f'{handler.config.get_application_config_subject_item("system_information", "windows_version")} / {handler.config.get_application_config_subject_item("system_information", "windows_build")}')
        self.label_windows_build.setToolTip(f'{handler.config.get_application_config_subject_item("system_information", "windows_version")} / {handler.config.get_application_config_subject_item("system_information", "windows_build")}')
        self.label_bios_version.setText(handler.config.get_application_config_subject_item("system_information", "pc_bios_version"))
        self.label_bios_version.setToolTip(handler.config.get_application_config_subject_item("system_information", "pc_bios_version"))
        self.label_servicetag.setText(handler.config.get_application_config_subject_item("system_information", "pc_servicetag"))
        self.label_servicetag.setToolTip(handler.config.get_application_config_subject_item("system_information", "pc_servicetag"))
        self.label_windows_productkey.setText(handler.config.get_application_config_subject_item("system_information", "windows_productkey"))
        self.label_windows_productkey.setToolTip(handler.config.get_application_config_subject_item("system_information", "windows_productkey"))


        # Set counter for started threads
        self.counter_threads = 0

        # Initil checks
        # self.windows7_check()
        # self.usb_check()
        # self.energy_check()
        if handler.SystemChecks.is_windows_server():
            self.infobox(
                f'Windows versie: {self.windows_version}\nHierdoor zijn de volgende opties niet beschikbaar\nPolicy, USB, Energiebeheer')
            self.pushButton_sec_policy.setEnabled(False)
            self.pushButton_usb_enable.setEnabled(False)
            self.pushButton_usb_disable.setEnabled(False)
            self.pushButton_energy_on.setEnabled(False)
            self.pushButton_energy_lock.setEnabled(False)
            self.pushButton_energy_default.setEnabled(False)

        # if handler.check_update_wdt() == 'New Version':
            # self.self.infobox_update(
                # f'v{new_version} is nu beschikbaar om te installeren.\n Wil je deze nu downloaden?')
            # self.statusBar().showMessage(f'Nieuwe versie beschikbaar v{new_version}')
        # if update_check == 'Connection Error':
        #     self.warningbox('Het is niet mogelijk om te controleren op updates\nControleer de internetverbinding')
        if handler.check_update_wdt() == 'Latest Version':
            self.infobox(f'Je maakt momenteel gebruik van de nieuwste versie (v{handler.wdt_current_version()})')

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
        self.pushButton_info_username.setIcon(QIcon(QPixmap(icon_circle_info)))
        self.pushButton_info_password.setIcon(QIcon(QPixmap(icon_circle_info)))
        self.pushButton_info_password.clicked.connect(self.open_password_notification_window)
        self.pushButton_info_username.clicked.connect(self.open_username_notification_window)
        self.pushButton_info_username.setToolTip('Klik voor info over Gebruikersnaam')
        self.pushButton_info_password.setToolTip('Klik voor info over Wachtwoord')
        self.pushButton_users_add_row.clicked.connect(self.table_add_row)

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

        # Add OEM information
        self.pushButton_add_oem_info.clicked.connect(self.add_oem_info)

        # Energy settings
        self.pushButton_energy_on.clicked.connect(self.energy_on)
        self.pushButton_energy_lock.clicked.connect(self.energy_lock)
        self.pushButton_energy_default.clicked.connect(self.energy_restore)

        # Systemcontrol
        self.pushButton_systemcontrol.clicked.connect(self.system_checks)

        # Restart system
        self.pushButton_restart_system.clicked.connect(self.restart_system)

        # Update button
        self.actioncheck_update_wdt.triggered.connect(self.check_for_update)

        # Create report button:
        self.pushButton_export_system_settings.clicked.connect(self.create_pdf_report)

        # Set date for report
        datetime = QDateTime.currentDateTime()
        self.dateEdit_date.setDateTime(datetime)

        # Set NTP Server / Client
        self.pushButton_ntp_server_enable.clicked.connect(self.activate_ntp_server)
        self.pushButton_ntp_client_enable.clicked.connect(self.activate_ntp_client)

        self.add_user_table = BaseTable(self.tableWidget_add_users)
        self.get_users_table = BaseTable(self.tableWidget_active_users)



    # # WDT update check
    # def check_update_wdt(self):
    #     url = 'https://raw.githubusercontent.com/jebr/windows-deployment-tool/master/version.txt'
    #     try:
    #         resp = requests.get(url, timeout=2)
    #     except Exception as e:
    #         # logging.error(f'{e}')
    #         return ('Connection Error')
    #     if not resp.ok:
    #         # logging.error(f'{resp.status_code}')
    #         # logging.error(f'{resp.text}')
    #         return ('Connection Error')
    #     latest_version = float(resp.text)
    #     self.new_version = latest_version
    #     if latest_version <= handler.wdt_current_version():
    #         return ('Latest Version')
    #     return ('New Version')

    # Systeemcontrole button
    @thread
    def system_checks(self):
        self.counter_threads = 0
        # self.pushButton_system_check.setEnabled(False)

        self.windows_chars()
        # self.secpol_check()
        # self.rdp_check()
        # self.fw_icmp_check()
        # self.fw_discovery_check()
        # self.energy_check()
        # self.get_users()
        # self.support_info_check()
        # self.check_ntp_server()
        # self.check_ntp_client()

        while True:
            # print(self.counter_threads)
            if self.counter_threads == 10: # Verhogen als er meer threads in
                # deze functie geplaatst worden
                break
            time.sleep(0.05)
        self.pushButton_export_system_settings.setEnabled(True)
        self.pushButton_system_check.setEnabled(True)

    # def windows7_check(self):
    #     os_version = platform.platform()
    #     if "Windows-7" in os_version:
    #         self.warningbox('****** BELANRIJKE MEDEDELING! ******\n\n'
    #                         'Windows 7 wordt niet meer ondersteund door Microsoft\n\n'
    #                         'Niet alle functionaliteit in de applicatie zal werken zoals verwacht\n\n'
    #                         'Dringend advies: Update de Pc naar Windows 10!')
    #         logging.error(f'Initial check: Windows 7 is not supported')

        

    @thread
    def support_info_check(self):
        oem_info_path = 'Registry::"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation"'
        oem_reg_sz = "Manufacturer"
        support_info_check = powershell([f'Get-ItemProperty -Path {oem_info_path} -Name {oem_reg_sz}'])
        if "Heijmans" in support_info_check:
            # logging.info('Support info check: Support info added')
            self.pushButton_check_support_info.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_add_oem_info_check.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.support_info_check_return = True
        else:
            # logging.info('Support info check: No Support info added')
            self.pushButton_check_support_info.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_add_oem_info_check.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.support_info_check_return = False
        self.counter_threads += 1

    def open_update(self):
        try:
            powershell(['C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate'])
        except Exception as e:
            pass
            # logging.info('Openen Windows update is mislukt.')

    @thread
    def get_users(self):
        if "Windows-7" in self.os_version:
            w7_users = powershell(['Get-WmiObject -Class Win32_UserAccount -Filter {LocalAccount="True" and Disabled="False"} | Select Name, Disabled'])
            w7_users_output = w7_users.splitlines()
            # logging.error(w7_users_output)
            w7_group_admin = powershell(['net localgroup administrators'])
            self.get_users_table.clearContents()
            i = 0
            for user in w7_users_output:
                if "False" not in user:
                    continue
                rowcount = self.get_users_table.get_rows()
                if rowcount == i:
                    self.get_users_table.add_row()
                new_user = user.replace('False', "").replace(" ", "")
                self.get_users_table.set_item(i, 0, new_user)
                if new_user in w7_group_admin:
                    self.get_users_table.set_item(i, 1, 'Ja')
                else:
                    self.get_users_table.set_item(i, 1, 'Nee')
                i += 1
            self.counter_threads += 1
        else:
            w_users = powershell(['Get-LocalUser | select name, enabled'])
            w_users_output = w_users.splitlines()
            w_group_admin = powershell(['net localgroup administrators'])
            self.get_users_table.clearContents()
            i = 0
            for user in w_users_output:
                if 'True' not in user:
                    continue
                rowcount = self.get_users_table.get_rows()
                if rowcount == i:
                    self.get_users_table.add_row()
                new_user = user.replace('True', "").replace(" ", "")
                self.get_users_table.set_item(i, 0, new_user)
                if new_user in w_group_admin:
                    self.get_users_table.set_item(i, 1, 'Ja')
                else:
                    self.get_users_table.set_item(i, 1, 'Nee')
                i += 1
            self.counter_threads += 1

    @thread
    def firewall_ping(self):
        if "nl" in self.os_language:
            try:
                powershell(['Set-NetFirewallRule -DisplayName \"Bestands- en '
                                 'printerdeling (Echoaanvraag - ICMPv4-In)\" -Profile Any -Enabled True'])
                self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                # logging.info('Firewall ICMP activated')
            except Exception as e:
                pass
                # logging.error(f'Firewall ICMP failed with message: {e}')
        else:
            try:
                powershell(['Set-NetFirewallRule -DisplayName \"File and Printer Sharing '
                                 '(Echo Request - ICMPv4-In)\" -Profile Any -Enabled True'])
                self.pushButton_check_fw_icmp.setIcon(QIcon(QPixmap(icon_circle_check)))
                # logging.info('Firewall ICMP activated')
            except Exception as e:
                pass
                # logging.error(f'Firewall ICMP failed with message: {e}')

    @thread
    def firewall_network_discovery(self):
        if "nl" in self.os_language:
            out = powershell(['netsh advfirewall firewall set rule group=”Netwerk detecteren” new enable=Yes'])
            if not out.strip().endswith('Ok.'):
                # logging.error(f'Firewall Discovery failed with message: {out.strip()}')
                self.warningbox('Functie niet uitgevoerd, zie logging voor meer info.')
            else:
                self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                # logging.info('Firewall Discovery activated')
        elif "en" in self.os_language:
            try:
                powershell(['netsh advfirewall firewall set rule group=”Network Discovery” new enable=Yes'])
                self.pushButton_check_fw_discovery.setIcon(QIcon(QPixmap(icon_circle_check)))
                # logging.info('Firewall Discovery activated')
            except Exception as e:
                pass
                # logging.error(f'Firewall Discovery failed with message: {e}')
        else:
            # logging.error(f'Language {self.os_language} is not supported.')
            self.warningbox('Functie niet uitgevoerd, zie logging voor meer info.')

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
            powershell([f'Rename-Computer -NewName {new_hostname}'])
            # subprocess.check_call(['powershell.exe', f'Rename-Computer -NewName {new_hostname}'])
            self.label_hostname_new.setText(f'Nieuwe computernaam: {new_hostname}')
            self.lineEdit_hostname.clear()
            # logging.info(f'Hostname changed to: {new_hostname}')
        except Exception as e:
            pass
            # logging.error(f'Hostname change failed with message: {e}')

    # Security
    @thread
    def import_sec_policy(self):
        global secpol_new
        if not os.path.exists(secpol_new):
            self.criticalbox('Kan secpol_new.inf niet vinden \nFunctie kan niet uitgevoerd worden!')
            # logging.info('secpol_new.inf is not found on the system. Execution of security policy failed')
        else:
            current_user_Desktop = 'c:\\users\\{}\\desktop'.format(getpass.getuser())
            program_cwd = os.getcwd()

            # Backup maken van de huidige security policy
            try:
                os.chdir("c:\\windows\\system32")
                powershell(['c:\\windows\\system32\\secedit '
                                 '/export /cfg backup_secpol.inf '
                                 '/log c:\\windows\\system32\\secpol_backup.log /quiet'])
                # logging.info('Backup of default security policy succesful')
                try:
                    shutil.copy('backup_secpol.inf', current_user_Desktop)  # Copy secpol_backup to user desktop
                    # logging.info(f'backup_secpol.inf is moved to {current_user_Desktop}')
                except Exception as e:
                    self.criticalbox('Copy of backup_secpol.inf failed with message: {e}')
            except Exception as e:
                pass
                # logging.info(f'Backup of security policy failed with message: {e}')
            finally:
                os.chdir(program_cwd)

            # Testen op een NL systeem
            try:
                # Copy secpol_new to c:\windows\system32
                shutil.copy(secpol_new, 'c:\\windows\\system32')
                # Import secpol_new policy
                try:
                    powershell([f'c:\\windows\\system32\\secedit /configure '
                                     f'/db c:\\windows\\system32\\defltbase.sdb /cfg {secpol_new} '
                                     f'/overwrite /log c:\\windows\\system32\\secpol_import.log '
                                     f'/quiet'])
                    # logging.info('Import security policy succesful')
                    try:
                        powershell(['echo y | gpupdate /force /wait:0'])
                        self.pushButton_check_secpol.setIcon(QIcon(QPixmap(icon_circle_check)))
                        # FIXME: Controleren of de gebruiker uitgelogd moet worden na het aanpassen van de policy of
                        # FIXME: pas na het doorlopen van het programma
                        # try:
                        #     subprocess.check_call(['powershell.exe', 'shutdown -L'])
                        # except Exception as e:
                        #     logging.info(str(e))
                        # logging.info('GPUpdate forced succesful')
                    except Exception as e:
                        pass
                        # logging.error(f'GPUpdate failed with message: {e}')
                except Exception as e:
                    pass
                    # logging.info(f'Import security policy failed with message: {e}')
            except Exception as e:
                pass
                # logging.error(f'Copy of {secpol_new} to c:\\windows\\system32 failed with message: {e}')

    # Functie voor het contoleren van de USB activering
    @thread
    def usb_check(self):
        self.usb_register_path = "Registry::HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
        self.usb_reg_dword = "Start"
        # Controleer de waarde van het register
        self.check_usb = powershell([f'Get-ItemProperty -Path {self.usb_register_path} -Name {self.usb_reg_dword}'])
        # self.check_usb = str(subprocess.check_output(['powershell.exe', 'Get-ItemProperty -Path {} -Name {}'.format(self.usb_register_path, self.usb_reg_dword)]))
        # Als de waarde 3 is de USB geactiveerd
        if "3" in self.check_usb:
            self.pushButton_usb_enable.setDisabled(True)
            self.pushButton_usb_disable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_transparant_image)))
            # logging.info('Initial check: USB-storage Enabled')
            self.usb_check_return = False
        # Als de waarde 4 is de USB gedeactiveerd
        elif "4" in self.check_usb:
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_circle_check)))
            # logging.info('Initial check: USB-storage Disabled')
            self.usb_check_return = True
        else:
            self.usb_check_return = False
            # logging.error('USB-storage check failed. Value of register doesn\'t match number 3 or 4.')

    @thread
    def enable_usb(self):
        try:
            powershell(['reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet'
                             '\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f'])
            self.pushButton_usb_enable.setDisabled(True)
            self.pushButton_usb_disable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_transparant_image)))
            # logging.info('USB-storage enabled')
        except Exception as e:
            pass
            # logging.error(f'Enable USB-storage failed with message: {e}')

    @thread
    def disable_usb(self):
        try:
            powershell(['reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet'
                             '\\Services\\USBSTOR /v Start /t REG_DWORD /d 4 /f'])
            self.pushButton_usb_disable.setDisabled(True)
            self.pushButton_usb_enable.setDisabled(False)
            self.pushButton_check_usb_enable.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_usb_disable.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_usb.setIcon(QIcon(QPixmap(icon_circle_check)))
            # logging.info('USB-storage disabled')
        except Exception as e:
            self.criticalbox(f'Disable USB-storage failed with message: {e}')

    # Wimndows settings
    @thread
    def enable_rdp(self):
        if self.rdp_check():
            # logging.info('RDP is al geactiveerd op deze computer')
            return
        else:
            if "nl" in self.os_language:
                try:
                    powershell(['Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                     'Gebruikersmodus (TCP-In)\" -Profile Any -Enabled True'])
                    powershell(['Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                     'Gebruikersmodus (UDP-In)\" -Profile Any -Enabled True'])
                    powershell(['Set-NetFirewallRule -DisplayName \"Extern bureaublad - '
                                     'Schaduw (TCP-In)\" -Profile Any -Enabled True'])
                    # logging.info('Firewall instellingen voor RDP zijn geactiveerd')
                except Exception as e:
                    pass
                    # logging.error(f'Firewall settings RDP failed with message: {e}')
            elif "en" in self.os_language:
                try:
                    powershell(['Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                     'User Mode (TCP-In)\" -Profile Any -Enabled True'])
                    powershell(['Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                     'User Mode (UDP-In)\" -Profile Any -Enabled True'])
                    powershell(['Set-NetFirewallRule -DisplayName \"Remote Desktop - '
                                     'Shadow (TCP-In)\" -Profile Any -Enabled True'])
                    # logging.info('Firewall instellingen voor RDP zijn geactiveerd')
                except Exception as e:
                    pass
                    # logging.error(f'Firewall settings RDP failed with message: {e}')
            try:
                powershell(['reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f'])
                powershell(['reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\" /v SecurityLayer /t REG_DWORD /d 0 /f'])
                powershell(['reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f'])
                # logging.info('De register wijzigingen voor RDP zijn geslaagd')
                self.pushButton_check_rdp.setIcon(QIcon(QPixmap(icon_circle_check)))
            except Exception as e:
                pass
                # logging.error(f'Register settings for RDP failed with message: {e}')

    # Energy Settings
    @thread
    def energy_on(self):
        global energy_config_on
        energy_on_scheme = '00000000-0000-0000-0000-000000000000'

        scheme_list = powershell(['powercfg /list'])

        active_scheme = powershell(['powercfg /getactivescheme'])

        # Check active scheme
        if energy_on_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
            return

        if energy_on_scheme in scheme_list:
            try:
                powershell([f'powercfg /delete {energy_on_scheme}'])
                try:
                    powershell([f'powercfg -import {energy_config_on} {energy_on_scheme}'])
                    powershell([f'powercfg -setactive {energy_on_scheme}'])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    # logging.info('Energy plan: always on activated')
                except Exception as e:
                    pass
                    # logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                pass
                # logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                powershell([f'powercfg -import {energy_config_on} {energy_on_scheme}'])
                powershell([f'powercfg -setactive {energy_on_scheme}'])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_circle_check)))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                # logging.info('Energy plan: always on activated')
            except Exception as e:
                pass
                # logging.error(f'Import energy plan failed with message {e}')

    @thread
    def energy_lock(self):
        global energy_config_lock
        energy_lock_scheme = '39ff2e23-e11c-4fc3-ab0f-da25fadb8a89'

        scheme_list = powershell(['powercfg /list'])

        active_scheme = powershell(['powercfg /getactivescheme'])

        # Check active scheme
        if energy_lock_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
            return

        if energy_lock_scheme in scheme_list:
            try:
                powershell([f'powercfg /delete {energy_lock_scheme}'])
                try:
                    powershell([f'powercfg -import {energy_config_lock} {energy_lock_scheme}'])
                    powershell([f'powercfg -setactive {energy_lock_scheme}'])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
                    # logging.info('Energy plan: Auto lock activated')
                except Exception as e:
                    pass
                    # logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                pass
                # logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                powershell([f'powercfg -import {energy_config_lock} {energy_lock_scheme}'])
                powershell([f'powercfg -setactive {energy_lock_scheme}'])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_circle_check)))
                # logging.info('Energy plan: Auto lock activated')
            except Exception as e:
                pass
                # logging.error(f'Import energy plan failed with message {e}')

    @thread
    def energy_restore(self):
        global energy_config_default
        energy_default_scheme = '381b4222-f694-41f0-9685-ff5bb260df2e'

        scheme_list = powershell(['powercfg /list'])

        active_scheme = powershell(['powercfg /getactivescheme'])

        # Check active scheme
        if energy_default_scheme in active_scheme:
            self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
            self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
            self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
            return

        if energy_default_scheme in scheme_list:
            try:
                powershell([f'powercfg /delete {energy_default_scheme}'])
                try:
                    powershell([f'powercfg -import {energy_config_default} {energy_default_scheme}'])
                    powershell([f'powercfg -setactive {energy_default_scheme}'])
                    self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
                    self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                    # logging.info('Energy plan: Default activated')
                except Exception as e:
                    pass
                    # logging.error(f'Import energy plan failed with message {e}')
            except Exception as e:
                pass
                # logging.info(f'Remove old energy plan failed with message: {e}')
        else:
            try:
                powershell([f'powercfg -import {energy_config_default} {energy_default_scheme}'])
                powershell([f'powercfg -setactive {energy_default_scheme}'])
                self.pushButton_check_energy_on.setIcon(QIcon(QPixmap(icon_transparant_image)))
                self.pushButton_check_energy_default.setIcon(QIcon(QPixmap(icon_circle_check)))
                self.pushButton_check_energy_lock.setIcon(QIcon(QPixmap(icon_transparant_image)))
                # logging.info('Energy plan: Default activated')
            except Exception as e:
                pass
                # logging.error(f'Import energy plan failed with message {e}')

    # Restart system
    def restart_system(self):
        try:
            powershell(['shutdown -r -t 10'])
            self.infobox('Het systeeem zal over 10 seconden herstarten')
        except Exception as e:
            self.warningbox('Door een onbekende fout kan het systeem niet herstart worden\nProbeer het systeem handmatig te herstarten')
            # logging.info('Systeem kan niet herstart worden. {}'.format(e))

    # Add Local Windows Users
    def load_csv_file(self):
        # self.clear_users_table()
        fileName, _ = QFileDialog.getOpenFileName(self,
                                                  "selecteer cvs bestand", "", "csv (*.csv)")
        if not fileName:
            # If window is clicked away
            return
        row_count = self.add_user_table.get_rows()
        with open(fileName) as csvfile:
            readCSV = csv.reader(csvfile, delimiter=',')
            # Get the first non empty row number
            for i in range(row_count):
                if not self.add_user_table.get_item(i, 0):
                    break
            # Append the data from cvs to the table
            try:
                for row in readCSV:
                    if i == row_count:
                        self.add_user_table.add_row()
                        row_count += 1
                    for j in range(5):
                        if j == 4:
                            if row[j].lower() == 'ja':
                                self.add_user_table.set_item(i, j, 'Ja')
                            else:
                                self.add_user_table.set_item(i, j, 'Nee')
                        else:
                            self.add_user_table.set_item(i, j, row[j])
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
        w_users = powershell(['(Get-LocalUser).name']).splitlines()
        w_users_enabled = powershell(['(Get-LocalUser).enabled']).splitlines()
        w_users_desc = powershell(['(Get-LocalUser).description']).splitlines()
        w_users_fullname = powershell(['(get-wmiobject -class Win32_USeraccount).fullname']).splitlines()
        w_group_admin = powershell(['net localgroup administrators'])
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
        w_users = powershell(['(Get-LocalUser).name']).splitlines()
        w_users = [element.lower() for element in w_users]  # Gebruikers naar lowercase
        for i in range(self.add_user_table.get_rows()):
            empty_fields = []

            user = self.add_user_table.get_item(i, 0).lower()
            if not user:
                empty_fields.append(f'Gebruikersnaam')

            password = self.add_user_table.get_item(i, 1)
            if not password:
                empty_fields.append(f'Wachtwoord')

            fullname = self.add_user_table.get_item(i, 2)
            if not fullname:
                empty_fields.append(f'Volledige Naam')

            desc = self.add_user_table.get_item(i, 3)
            if not desc:
                empty_fields.append(f'Beschrijving')

            admin = self.add_user_table.get_item(i, 4)
            if not admin:
                empty_fields.append('Administrator')

            if len(empty_fields) == 5:
                continue

            if empty_fields:
                self.warningbox(f'De volgende velden zijn niet ingevuld in rij {i + 1}: \n - ' + '\n - '.join(empty_fields))
                return False

            # Admin veld Ja/ja en anders nee
            admin = True if admin.lower() == 'ja' else False

            if not self.checkout_username(user):
                self.criticalbox(self.username_fault)
                return False

            if not self.checkout_password(password=password, sam_account_name=user, display_name=fullname):
                self.criticalbox(self.password_fault)
                return False

            # Check of de gebruiker al voorkomt op de computer
            if user.lower() in w_users:
                self.warningbox(f'De gebruiker "{user}" komt al voor op deze computer en kan niet toegevoegd. '
                                f'Verander de gebruikersnaam.')
                return False
            try:
                user = user.replace(' ', '')
                user = user.capitalize()
                powershell([f'net user "{user}" "{password}" /add /active:yes '
                                 f'/fullname:"{fullname}" /comment:"{desc}" /expires:never /Y'])
                powershell([f'wmic useraccount where "name=\'{user}\'" set PasswordExpires=False '])
                # subprocess.check_call(['powershell.exe', f'$password = {password} -AsSecureString && New-LocalUser "{user}" -Password $password -Fullname {fullname} -Description {desc}'])
                self.tableWidget_add_users.setItem(i, 0, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 1, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 2, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 3, QTableWidgetItem(''))
                self.tableWidget_add_users.setItem(i, 4, QTableWidgetItem(''))
                self.infobox(f'De gebruiker {user} is succesvol toegevoegd\n')
                if admin == True:
                    try:
                        powershell([f'Add-LocalGroupMember -Group "Administrators" -Member {user}'])
                    except Exception as e:
                        pass
                        # logging.error(f'User {user} can not be added to the administrators group. Error message: {e}')
                # logging.info(f'User {user} is successfully added as local user to this computer')
            except Exception as e:
                pass
                # logging.error(f'User {user} can not be added. Error message: {e}')

    def checkout_username(self, samAccountName):
        self.username_fault = ''
        if len(samAccountName) > 20:
            self.username_fault = ('De gebruikersnaam bevat teveel karakters. Maximaal 20 karakters toegestaan')
            return False
        prohobited = '\\/:*?\"<>|,@[];=+'
        # " / \ [ ] : ; | = , + * ? < > @
        for elem in prohobited:
            if elem in samAccountName:
                self.username_fault = ('De gebruikersnaam bevat ongeldige tekens.')
                return False
        if samAccountName.replace(' ','') == '':
            self.username_fault = ('De gebruikersnaam mag niet uit spaties bestaan.')
            return False
        if samAccountName.replace('.','.') == '.':
            self.username_fault = ('De gebruikersnaam mag niet uit punten bestaan.')
            return False
        if samAccountName.lower() == powershell(['hostname']).lower().rstrip():
            self.username_fault = ('De gebruikersnaam mag niet hetzelfde zijn als de computernaam.')
            return False
        if samAccountName.lower().endswith(' '):
            self.username_fault = ('De gebruikersnaam mag niet eindigen met een spatie')
            return False
        if samAccountName.lower().startswith(' '):
            self.username_fault = ('De gebruikersnaam mag niet beginnen met een spatie')
            return False
        return True

    def clear_users_table(self):
        self.tableWidget_add_users.clearContents()

    def table_add_row(self):
        self.add_user_table.add_row()

    def create_pdf_report(self):
        if not self.lineEdit_project.text():
            self.warningbox('Vul de naam van het project in')
            # logging.error('Project field not filled in')
            return False
        elif not self.lineEdit_engineer.text():
            self.warningbox('Vul je voor- en achternaam in')
            # logging.error('Engineer field not filled in')
            return False
        else:
            self.create_pdf_report_thread()

    @thread
    def create_pdf_report_thread(self):
        date_time = datetime.now().strftime('%d%m%Y%H%M%S')
        hostname = self.hostname
        project = self.lineEdit_project.text()
        engineer = self.lineEdit_engineer.text()
        filename = f'c:\\users\\{handler.current_user}\\Desktop\\deploy_report_{project}_{hostname}.pdf'

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
            <br/>
            <font size=16><b>{self.lineEdit_project.text()}</b><br/><br/></font>
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
            <br/>
            Windows Deployment Tool v{handler.wdt_current_version()}
            </font>
            '''
            para_character_data = Paragraph(character_data, style=styles['Normal'])
            para_character_data.wrapOn(my_canvas, width, height)
            para_character_data.drawOn(my_canvas, 50, 175)

            # Footer
            footer_text = '''
            <font size=6>Heijmans Utiliteit B.V. • Graafsebaan 65, 5248 JT  Rosmalen • Postbus 246, 5240 AE  Rosmalen • 
            Nederland<br/> 
            Telefoon +31 (0)73 543 51 11 • E-mail info@heijmans.nl • Website www.heijmans.nl<br/>
            Niets van dit rapport en/of ontwerp mag worden vermenigvuldigd, openbaar gemaakt en/of overhandigd aan derden, 
            zonder voorafgaande schriftelijke toestemming van de samensteller.</font>
            '''
            para_footer = Paragraph(footer_text, style=styles['Normal'])
            para_footer.wrapOn(my_canvas, width, height)
            para_footer.drawOn(my_canvas, 50, 20)
            # Page number
            para_page_number_1 = Paragraph('<font size=6>pagina 1 van 3</font>', style=styles['Normal'])
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
            title_system_info.drawOn(my_canvas, 50, 740)
            system_info_data = [
                ['Windows Versie', str(self.label_windows_version.text())],
                ['Windows Taal', str(self.label_windows_lang.text())],
                ['Domein / Werkgroep', self.label_domain_workgroup.text()],
                ['Computernaam', self.label_windows_hostname.text()],
                ['Fabrikant / Model', self.label_manufacturer_model.text()],
                ['Type', self.label_type.text()],
                ['RAM', self.label_physicalmemory.text()],
                ['Processor', self.label_processor.text()],
                ['Core / Logical Processors', self.label_cores.text()],
                ['Windows Version / Build', self.label_windows_build.text()],
                ['BIOS Versie', self.label_bios_version.text()],
                ['Servicetag', self.label_servicetag.text()]
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
            support_info_added = 'Ja' if self.support_info_check_return else 'Nee'
            ntp_server_enabled = 'Ja' if self.ntp_server_return else 'Nee'

            application_settings_data = [
                ['Security Policy toegepast', secpol_enabled],
                ['USB geblokkeerd', usb_blocked],
                ['Remote Desktop geactiveerd', rdp_enabled],
                ['Windows Firewall ICMP toegestaan', icmp_enabled],
                ['Windows Firewall Discovery toegestaan', discovery_enabled],
                ['Energiebeheer', self.label_energie_settings.text()],
                ['Support Info toegevoegd', support_info_added],
                ['NTP server', ntp_server_enabled],
                ['NTP client', self.label_ntp_server_address.text()]
            ]
            table_application_settings = Table(application_settings_data, style=[('OUTLINE', (0, 0), (-1, -1), 0.25, colors.black),
                                                                                 ('LINEAFTER', (0, 0), (0, -1), 0.25, colors.black)], colWidths=250)
            table_application_settings.wrapOn(my_canvas, width, height)
            table_application_settings.drawOn(my_canvas, 50, 310)

            # Footer
            para_footer.drawOn(my_canvas, 50, 20)
            # Page number
            para_page_number_1 = Paragraph('<font size=6>pagina 2 van 3</font>', style=styles['Normal'])
            para_page_number_1.wrapOn(my_canvas, width, height)
            para_page_number_1.drawOn(my_canvas, width / 2, 5)

            # Page Break
            my_canvas.showPage()

            # Page 3
            my_canvas.drawImage(icon_heijmans_logo, 400, 770, 156.35, 39.6)
            para_logo_sub.drawOn(my_canvas, 400, 755)

            # Body
            # Windows Users
            title_windows_users = Paragraph('<font size=14><b>Lokale Windows Gebruikers</b></font>',
                                            style=styles['Normal'])
            title_windows_users.wrapOn(my_canvas, width, height)
            title_windows_users.drawOn(my_canvas, 50, 740)

            windows_users_data = [['Gebruiker', 'Administrator']]
            height_windows_users_table = 690
            rowcount = self.get_users_table.get_rows()
            for i in range(rowcount):
                try:
                    user_cell = self.tableWidget_active_users.item(i, 0)
                    admin_cell = self.tableWidget_active_users.item(i, 1)
                    if 'text' not in dir(user_cell) or 'text' not in dir(admin_cell):
                        continue
                    user_cell = user_cell.text()
                    admin_cell = admin_cell.text()
                    windows_users_data.append([user_cell, admin_cell])
                    height_windows_users_table -= 18
                except Exception as e:
                    pass
                    # logging.error(f'Error message: {e}')

            table_windows_user_data = Table(windows_users_data,
                                            style=[('OUTLINE', (0, 0), (-1, -1), 0.25, colors.black),
                                                   ('LINEAFTER', (0, 0), (0, -1), 0.25, colors.black),
                                                   ('LINEBELOW', (0, 0), (-1, 0), 0.25, colors.black)], colWidths=250)
            table_windows_user_data.wrapOn(my_canvas, width, height)
            table_windows_user_data.drawOn(my_canvas, 50, height_windows_users_table)

            # Footer
            para_footer.drawOn(my_canvas, 50, 20)
            # Page number
            para_page_number_1 = Paragraph('<font size=6>pagina 3 van 3</font>', style=styles['Normal'])
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

            powershell([f'start "{filename}"'])
        except Exception as e:
            pass
            # logging.error(f'Deployment report failed with message: {e}')

    @thread
    def add_oem_info(self):
        manufacturer_pc = powershell(['(get-wmiobject Win32_ComputerSystem).manufacturer']).strip()
        model_pc = powershell(['(get-wmiobject Win32_ComputerSystem).model']).strip()
        servicetag = powershell(['(Get-WmiObject -class Win32_Bios).serialnumber']).strip()
        manufacturer = 'Heijmans Utiliteit Safety & Security'
        supporthours = '24/7'
        supportphone = '+31 (0) 88 443 50 03'
        supporturl = 'https://www.heijmans.nl'
        try:
            powershell([f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation" /v Manufacturer /t REG_SZ /d "{manufacturer}" /f'])
            powershell([f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation" /v Logo /t REG_SZ /d "{icon_heijmans_logo_square}" /f'])
            powershell([f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation" /v Model /t REG_SZ /d "{manufacturer_pc} {model_pc}" /f'])
            powershell([f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation" /v SupportHours /t REG_SZ /d "{supporthours}" /f'])
            powershell([f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation" /v SupportPhone /t REG_SZ /d "{supportphone}" /f'])
            powershell([f'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OEMInformation" /v SupportURL /t REG_SZ /d "{supporturl}" /f'])

            # Add servicetag to computer description
            subprocess.check_call(['powershell.exe', f'net config server /srvcomment:"Servicetag: {servicetag}"'])
            self.pushButton_check_support_info.setIcon(QIcon(QPixmap(icon_circle_check)))
            # logging.info('Added support information')
        except Exception as e:
            pass
            # logging.error(f'Import support information failed with message {e}')

    @thread
    def activate_ntp_server(self):
        call = powershell(['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services'
                                '\\w32time\\TimeProviders\\NtpServer" -Name "Enabled" -Value 1'])
        if call.strip() != '':
            pass
            # logging.error(f'Activate NTP server failed with message: {call.strip()}')

        call = powershell(['Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\services'
                                '\\W32Time\\Config" -Name "AnnounceFlags" -Value 5'])
        if call.strip() != '':
            pass
            # logging.error(f'Activate NTP server failed with message: {call.strip()}')

        call = powershell(['netsh advfirewall firewall add rule name = "Allow NTP sync" '
                                'dir=in action=allow protocol=UDP localport=123'])
        if not call.strip().endswith('Ok.'):
            pass
            # logging.error(f'Activate NTP server failed with message: {call.strip()}')

        call = powershell(['Restart-Service w32Time'])
        if call.strip() != '':
            pass
            # logging.error(f'Activate NTP server failed with message: {call.strip()}')

        # logging.info(f'System check: NTP server enabled')
        self.pushButton_check_ntp_server.setIcon(QIcon(QPixmap(icon_circle_check)))

    def activate_ntp_client(self):
        self.ntp_server_address = self.lineEdit_ntp_client.text()
        if not self.ntp_server_address:
            self.warningbox('Voer het IP adres of de DNS naam in van de NTP server')
            return False
        else:
            self.activate_ntp_client_thread()

    @thread
    def activate_ntp_client_thread(self):
        call = powershell([f'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services'
                                f'\\w32time\\Parameters" -Name "NtpServer" -Value "{self.ntp_server_address},0x8"'])
        if call.strip() != '0':
            pass
            # logging.error(f'Activate NTP client failed with message: {call.strip()}')

        call = powershell(['Restart-Service w32Time'])
        if call.strip() != '0':
            pass
            # logging.error(f'Activate NTP client failed with message: {call.strip()}')
        self.label_ntp_server_address.setText(f'{self.ntp_server_address},0x8')
        self.pushButton_check_ntp_client.setIcon(QIcon(QPixmap(icon_circle_check)))
        self.lineEdit_ntp_client.setText('')

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

    def open_password_notification_window(self):
        password_window = PasswordNotificationWindow()
        password_window.exec_()

    def open_username_notification_window(self):
        password_window = UsernameNotificationWindow()
        password_window.exec_()


class HostnameWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(572, 382)
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
        self.label_info_title.setText(f'Windows Deployment Tool v{handler.wdt_current_version()} <br/> <font size=1>Heijmans N.V.</font>')
        self.label_info_link.setText('<a href="https://github.com/jebr/windows-deployment-tool">GitHub repository</a>')
        self.label_info_link.setOpenExternalLinks(True)
        self.label_info_dev.setText('Developers\nJeroen Brauns / Niels van den Bos')
        self.pushButton_update_check.clicked.connect(handler.open_releases_website)


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
        self.label_info_title.setText(f'Windows Deployment Tool v{handler.wdt_current_version()}')
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
        self.label_logging_title.setText(f'Windows Deployment Tool v{handler.wdt_current_version()}')
        self.label_info_company.setText('Heijmans N.V.')
        with open(f'c:\\users\\{handler.current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log') as file:
            license_text = file.read()
        self.plainTextEdit_logging.setPlainText(license_text)
        self.plainTextEdit_logging.centerCursor()
        self.plainTextEdit_logging.centerOnScroll()
        # Buttons
        self.pushButton_clear_log.clicked.connect(self.clear_wdt_log)
        self.pushButton_export_log.clicked.connect(self.export_wdt_log)
        self.pushButton_delete_log.clicked.connect(self.delete_wdt_log)

    def clear_wdt_log(self):
        with open(f'c:\\users\\{handler.current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log', 'w'): pass
        self.plainTextEdit_logging.clear()

    def export_wdt_log(self):
        wdt_log = self.plainTextEdit_logging.toPlainText()
        try:
            with open(f'C:\\Users\\{handler.current_user}\\Desktop\\WDT.log', 'w+') as file:
                file.write(wdt_log)
                self.infobox(f'WDT.log is opgeslagen op de locatie: C:\\Users\\{handler.current_user}\\Desktop.')
                try:
                    powershell([f'start c:\\users\\{handler.current_user}\\Desktop\\WDT.log'])
                except Exception as e:
                    self.infobox(f'Log kan niet automatisch geopend worden.\nError: {e}')
        except Exception as e:
            self.infobox(f'Log kan niet geexporteerd worden.\nError: {e}')

    def delete_wdt_log(self):
        self.infobox(f'WDT.log kan handmatig verwijderd worden nadat WDT is afgesloten.\n\nLocatie: '
                     f'C:\\Users\\{handler.current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log\n\n'
                     f'De verkenner zal geopend worden nadat op OK is geklikt.')
        try:
            powershell([f'start C:\\Users\\{handler.current_user}\\AppData\\Local\\Temp\\WDT'])
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

        self.local_admin_enabled = powershell(['(Get-LocalUser Administrator).enabled'])
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
        password = self.lineEdit_password_check.text()
        user = 'Administrator'
        fullname = 'Administrator'
        if not self.checkout_password(password=password, sam_account_name=user, display_name=fullname):
            self.criticalbox(self.password_fault)
            return False
        try:
            # Change Admin password without activate
            if not self.checkBox_activate_admin.isChecked() and not eval(self.local_admin_enabled):
                powershell([f'net user "Administrator" "{self.lineEdit_password.text()}" /add /expires:never /Y'])
                self.infobox(f'Let op!\nHet Administrator account is niet geactiveerd\nHet wachtwoord \"{self.lineEdit_password.text()}\" is ingesteld voor het Adminstrator account')
            # Activate Admin account with password
            elif self.checkBox_activate_admin.isChecked() and not eval(self.local_admin_enabled):
                powershell(['Enable-LocalUser Administrator'])
                powershell([f'net user "Administrator" "{self.lineEdit_password.text()}" /add /expires:never /Y'])
                self.infobox(f'Administrator account is geactiveerd met het wachtwoord \"{self.lineEdit_password.text()}\"')
            # Change Admin password for activated account
            elif self.checkBox_activate_admin.isChecked() and eval(self.local_admin_enabled):
                powershell([f'net user "Administrator" "{self.lineEdit_password.text()}" /add /expires:never /Y'])
                self.infobox(f'Het wachtwoord \"{self.lineEdit_password.text()}\" is ingesteld voor het Administrator account')
        except Exception as e:
            logging.error(f'Add Administrator account or change password failed. Error: {e}')

        # Close Window
        self.close()


class PasswordNotificationWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(572, 382)
        loadUi(ui_password_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))


class UsernameNotificationWindow(QDialog, BaseWindow):
    def __init__(self):
        super().__init__(None, QtCore.Qt.WindowCloseButtonHint)
        self.setFixedSize(572, 382)
        loadUi(ui_username_window, self)
        self.setWindowIcon(QtGui.QIcon(icon_window))
