import unittest

import WindowsProductKey

class TestWindowsProductKey(unittest.TestCase):

    def setUp(self) -> None:
        self.wk = WindowsProductKey()

    def test_write_product_key_to_file(self):
        result = self.wk.write_product_key_to_file()
        