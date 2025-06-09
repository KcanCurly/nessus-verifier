import subprocess
import re
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from src.utilities.utilities import error_handler

class TFTPBruteSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Run TFTP bruteforce on targets")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        pattern = r"\[\+\] Found (.*) on (\S*)"
        nmap_file = "/usr/share/nmap/nselib/data/tftplist.txt"
        result = ", ".join(host.ip for host in hosts)
        vuln = {}

        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set THREADS {self.threads}; set ConnectTimeout {self.timeout}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        
        matches = re.findall(pattern, result.stdout, re.MULTILINE)

        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
            
        command1 = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set DICTIONARY {nmap_file}; set THREADS {self.threads}; set ConnectTimeout {self.timeout}; run; exit"]
        result1 = subprocess.run(command1, text=True, capture_output=True)

        matches1 = re.findall(pattern, result1.stdout, re.MULTILINE)
        
        for m in matches1:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
            
        if vuln:
            self.print_output("TFTP files were found:")
            for k,v in vuln.items():
                self.print_output(f"{k}:")
                for a in v:
                    self.print_output(f"    {a}")
        
class TFTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("tftp")
        self.register_subservice(TFTPBruteSubServiceClass())
