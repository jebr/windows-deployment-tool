import subprocess
import sys
import os

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.environ.get("_MEIPASS2", os.path.abspath("."))
    return os.path.join(base_path, relative_path)

def add_stuff_to_firewall():
    subprocess.call(['netsh',
                     'advfirewall',
                     'firewall',
                     'add',
                     'rule',
                     'name=NTP (UDP-123)',
                     'protocol=UDP',
                     'dir=out',
                     'localport=123',
                     'action=allow'])
    return True

def add_stuff_to_registery():
    commands = ['reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server /v fDenyTSConnections /t REG_DWORD /d 0 /f',
    'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp /v SecurityLayer /t REG_DWORD /d 0 /f',
    'reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp /v UserAuthentication /t REG_DWORD /d 0 /f']
    for command in commands:
        subprocess.call(command.split(' '))

    rule_names = ['Extern bureaublad - Gebruikersmodus (TCP-In)',
                  'Extern bureaublad - Gebruikersmodus (UDP-In)',
                  'Extern bureaublad - Schaduw (TCP-In)']
    for elem in rule_names:
        tmp = 'netsh advfirewall firewall set rule name= new enable=yes'.split(' ')
        tmp[5] += elem
        subprocess.call(tmp)
    return True

def checkout_hostname(hostname):
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
