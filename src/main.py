import sys
import ctypes
from PyQt5.QtWidgets import QApplication
import handler as handler
from qthandler import MainPage

# try:
#     os.chdir(os.path.dirname(sys.argv[0]))
# except Exception:
#     pass


def main():
    # Run initial setup and config
    handler.initial_run()
    app = QApplication(sys.argv)
    widget = MainPage()
    widget.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    if handler.SystemChecks.is_started_as_admin():
        try:
            main()
        finally:
            handler.logger.write_to_file()
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
