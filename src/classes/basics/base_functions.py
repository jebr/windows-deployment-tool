import subprocess
import sys
import os
import functools
import threading
import logging
from datetime import datetime
from ..app_settings.app_settings import log_file_location


class UnexpectedPowershellOutput(Exception):
    pass


def escape_cmd(command):
    return command.replace('&', '^&')


def powershell(input_: list) -> str:
    """
    Returns a string when no error
    If an exception occurs the exeption is logged and None is returned
    """
    if sys.platform == 'win32':
        input_ = [escape_cmd(elem) for elem in input_]
    execute = ['powershell.exe'] + input_

    # if DEBUG:
    #     return ' '.join(execute)

    try:
        proc = subprocess.Popen(execute,
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                stdin=subprocess.PIPE,
                                cwd=os.getcwd(),
                                env=os.environ)
        proc.stdin.close()
        outs, errs = proc.communicate(timeout=15)
        if proc.returncode != 0:
            raise UnexpectedPowershellOutput(outs.decode('U8'))
        return outs.decode('U8')
    except Exception as e:
        # print(e)
        return f"{e}"
        # logging.warning(e)


def resource_path(relative_path):
    """
    Get absolute path to resource, works for dev and for PyInstaller
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.environ.get("_MEIPASS2", os.path.abspath("."))
    # logging.info('Pyinstaller file location {}'.format(base_path))
    return os.path.join(base_path, relative_path)


def thread(func, *args, **kwargs):
    @functools.wraps(func)
    def wrapper(**kwargs):
        if 'daemon' in kwargs:
            daemon = kwargs.pop('daemon')
        else:
            daemon = True
        t = threading.Thread(target=func, args=[*args], daemon=daemon)
        t.start()
    return wrapper


# def wdt_log(msg: str, lvl=0):
#     """
#     Log information to log file.
#     Levels:
#     0 - Debug
#     1 - Info
#     2 - Warning
#     3 - Error
#     4 - Critical
#      """
#     logging.basicConfig(level=logging.WARNING,
#                         format='%(asctime)s - %(levelname)s - %(message)s',
#                         filename=log_file_location,
#                         filemode='a')
#     # date_time = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
#     # Console logging alleen voor ontwikkeling, uitzetten bij een release
#     # define a Handler which writes INFO messages or higher to the sys.stderr
#     console = logging.StreamHandler()
#     console.setLevel(logging.DEBUG)
#     # set a format which is simpler for console use
#     formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
#     # tell the handler to use this format
#     console.setFormatter(formatter)
#     # add the handler to the root logger
#     logging.getLogger('').addHandler(console)
#     if lvl == 1:
#         return logging.info(msg)
#     elif lvl == 2:
#         return logging.warning(msg)
#     elif lvl == 3:
#         return logging.error(msg)
#     elif lvl == 4:
#         return logging.critical(msg)
#     else:
#         return logging.debug(msg)



