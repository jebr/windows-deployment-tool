import os
import json
from ..basics.base_functions import resource_path
from ..app_settings.app_settings import productkey_file_location


class WindowsProductKey:
    """
    Extraxt Windows Product Key
    The class uses ProduKey.exe from Nirsoft
    https://www.nirsoft.net/utils/product_cd_key_viewer.html
    """

    @staticmethod
    def write_product_key_to_file() -> str:
        """
        Use ProduKey.exe to extract Windows Product Key\n
        Data saved to w_key.json
        """
        nirsoft_product_key_finder = resource_path("resources/productkey/ProduKey.exe")
        if os.path.exists(nirsoft_product_key_finder):
            syntax = f"{nirsoft_product_key_finder} /WindowsKeys 1 " \
                     f"/OfficeKeys 0 /IEKeys 0 /ExtrackEdition 0 " \
                     f"/ExtractExchangeKeys 0 /ExtraxtSQLKeys 0 " \
                     f"/nosavereg /sjson " \
                     f"{productkey_file_location}"
            try:
                os.system(syntax)
                return f"File saved at " \
                       f"{productkey_file_location}"
            except Exception as e:
                return f"Error: {e}"
        else:
            return f"Error: ProduKey.exe not found at " \
                   f"{nirsoft_product_key_finder}"

    @staticmethod
    def extract_product_key() -> str:
        """Read Windows Product Key form w_key.json"""
        fn = productkey_file_location
        if not os.path.exists(fn):
            return f"Error: {fn} not found"

        with open(fn, "r") as file:
            data = json.load(file)
        if len(data) == 1:
            w_info = data[0]
        else:
            w_info = data[1]
        return w_info["Product Key"]

    @staticmethod
    def remove_product_key_json() -> str:
        """""Remove file with licence key data"""
        if os.path.exists(productkey_file_location):
            os.remove(productkey_file_location)
            return "File deleted"
        else:
            return "w_key.json doesn't exist"
