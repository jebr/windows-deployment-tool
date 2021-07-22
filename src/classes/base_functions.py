import subprocess
import sys
import os


class UnexpectedPowershellOutput(Exception):
    pass


class BaseFunctions:
    @staticmethod
    def escape_cmd(self, command):
        return command.replace('&', '^&')

    @staticmethod
    def powershell(self, input_: list) -> str:
        """
        Returns a string when no error
        If an exception occurs the exeption is logged and None is returned
        """
        if sys.platform == 'win32':
            input_ = [self.escape_cmd(elem) for elem in input_]
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
