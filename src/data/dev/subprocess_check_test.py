import subprocess

command = ['netsh', 'advfirewall', 'firewall', 'set', 'rule name="Extern bureaublad - Gebruikersmodus (TCP-In)"', 'new', 'enable=yes']

try:
  subprocess.check_call(command)
except subprocess.CalledProcessError:
  # There was an error - command exited with non-zero code
  print("De bewerking is mislukt")