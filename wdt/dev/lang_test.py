import locale
import ctypes
windll = ctypes.windll.kernel32
windll.GetUserDefaultUILanguage()
lang =locale.windows_locale[windll.GetUserDefaultUILanguage()]
print(lang)