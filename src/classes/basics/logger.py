from datetime import datetime
import os


class Logger:
    def __init__(self, file, verbose=True):
        self.file = file
        self.verbose = verbose
        self.content = ""
        if os.path.exists(file):
            self.content = "\n\n\n"

    def debug(self, text) -> None:
        log_text = self.get_time() + "INFO - " + text
        print(log_text)

    def info(self, text) -> None:
        log_text = self.get_time() + "INFO - " + text
        print(log_text)
        self.content += log_text  + "\n"

    def error(self, text) -> None:
        log_text = self.get_time() + "ERROR - " + text
        print(log_text)
        self.content += log_text + "\n"

    def critical(self, text) -> None:
        log_text = self.get_time() + "ERROR - " + text
        print(log_text)
        self.content += log_text + "\n"
        self.write_to_file()

    def write_to_file(self):
        if not self.file: return

        try:
            with open(self.file, "a") as f:
                f.write(self.content)
            self.content = ""
        except Exception as e:
            print('unable to write to file')

    @staticmethod
    def get_time() -> str:
        "returns time w/ format 2021-03-08T11:54:48.602655"
        now = datetime.now()
        return f"{now.isoformat()} - "


# OLD LOGGER


# Create temp folder
# current_user = getpass.getuser()
# if not os.path.exists(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT'):
#     os.makedirs(f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT')
#
# # Set logging
# logging.basicConfig(level=logging.INFO,
#                     format='%(asctime)s - %(levelname)s - %(message)s',
#                     filename=f'c:\\users\\{current_user}\\AppData\\Local\\Temp\\WDT\\WDT.log',
#                     filemode='a')
# date_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
# # logging.disable(logging.DEBUG)
# # FIXME Console logging alleen voor ontwikkeling, uitzetten bij een release
# # define a Handler which writes INFO messages or higher to the sys.stderr
# console = logging.StreamHandler()
# console.setLevel(logging.INFO)
# # set a format which is simpler for console use
# formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
# # tell the handler to use this format
# console.setFormatter(formatter)
# # add the handler to the root logger
# logging.getLogger('').addHandler(console)