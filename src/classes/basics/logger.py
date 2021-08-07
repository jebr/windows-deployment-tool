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
