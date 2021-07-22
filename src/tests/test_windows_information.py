import unittest

from windows_information import WindowsInformation
from powershell import powershell


class TestWindowsInformation(unittest.TestCase):

    def setUp(self) -> None:
        self.wi = WindowsInformation()

    def test_windows_operating_system(self):
        result = self.wi.windows_operating_system()
        hostname = powershell(["(Get-WmiObject Win32_OperatingSystem)"
                               ".Caption"]).rstrip()
        self.assertEqual(result, hostname)

    def test_windows_language(self):
        result = self.wi.windows_language()
        language = powershell(["(Get-Culture).DisplayName"]).rstrip()
        self.assertEqual(result, language)

    def test_domain_or_workgroup(self):
        result = self.wi.domain_or_workgroup()
        domain_workgroup = powershell(["(Get-WmiObject "
                                       "Win32_ComputerSystem)."
                                       "domain"]).rstrip()
        self.assertEqual(result, domain_workgroup)

    def test_computername(self):
        result = self.wi.computername()
        computername = powershell(["(Get-WMIObject "
                                   "Win32_ComputerSystem).name"]).rstrip()
        self.assertEqual(result, computername)

    def test_windows_release_build(self):
        result = self.wi.windows_release_build()
        release_build = powershell(["(Get-ItemProperty "
                                    "'HKLM:\\SOFTWARE\\Microsoft\\Windows "
                                    "NT\\CurrentVersion').ReleaseID"]).rstrip()
        self.assertEqual(result, release_build)

    def test_windows_release_version(self):
        result = self.wi.windows_release_version()
        release_version = powershell(["(Get-WmiObject "
                                      "Win32_OperatingSystem)."
                                      "Version"]).rstrip()
        self.assertEqual(result, release_version)


if __name__ == '__main__':
    unittest.main()
