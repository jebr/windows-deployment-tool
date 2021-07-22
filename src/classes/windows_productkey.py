import os
import json

import resource_path
# from resource_path import resource_path


class WindowsProductKey:
    """
    Extraxt Windows Product Key\n
    The class uses ProduKey.exe from Nirsoft\n
    https://www.nirsoft.net/utils/product_cd_key_viewer.html
    """

    @staticmethod
    def write_product_key_to_file() -> str:
        """
        Use ProduKey.exe to extract Windows Product Key\n
        Data saved to w_key.json
        """
        nirsoft_product_key_finder = resource_path("ProduKey.exe")
        if os.path.exists(nirsoft_product_key_finder):
            syntax = f"{nirsoft_product_key_finder} /WindowsKeys 1 " \
                     f"/OfficeKeys 0 /IEKeys 0 /ExtrackEdition 0 " \
                     f"/ExtractExchangeKeys 0 /ExtraxtSQLKeys 0 " \
                     f"/nosavereg /sjson " \
                     f"{resource_path('w_key.json')}"
            try:
                os.system(syntax)
                return f"File saved at " \
                       f"{resource_path('w_key.json')}"
            except Exception as e:
                return f"Error: {e}"
        else:
            return f"Error: ProduKey.exe not found at " \
                   f"{nirsoft_product_key_finder}"

    @staticmethod
    def extract_product_key() -> str:
        """Read Windows Product Key form w_key.json"""
        try:
            with open("w_key.json", "r") as file:
                data = json.load(file)
            if len(data) == 1:
                w_info = data[0]
            else:
                w_info = data[1]
            w_key = w_info["Product Key"]
            return f"{w_key}"
        except FileNotFoundError:
            return "Error: w_key.json not found"

