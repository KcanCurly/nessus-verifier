import subprocess
import re
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class TFTPBruteSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Run TFTP bruteforce on targets")


    def nv(self, hosts, **kwargs):
        pattern = r"\[\+\] Found (.*) on (\S*)"
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        nmap_file = "/usr/share/nmap/nselib/data/tftplist.txt"
        result = ", ".join(host.ip for host in hosts)
        vuln = {}
        try:
            command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set THREADS {threads}; set ConnectTimeout {timeout}; run; exit"]
            result = subprocess.run(command, text=True, capture_output=True)
            
            matches = re.findall(pattern, result.stdout, re.MULTILINE)

            for m in matches:
                if m[1] not in vuln:
                    vuln[m[1]] = set()
                vuln[m[1]].add(m[0])
                
            command1 = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set DICTIONARY {nmap_file}; set THREADS {threads}; set ConnectTimeout {timeout}; run; exit"]
            result1 = subprocess.run(command1, text=True, capture_output=True)

            matches1 = re.findall(pattern, result1.stdout, re.MULTILINE)
            
            for m in matches1:
                if m[1] not in vuln:
                    vuln[m[1]] = set()
                vuln[m[1]].add(m[0])
            
                
        except Exception as e:
            if errors: print(e)
        
        if len(vuln) > 0:
            print("TFTP files were found:")
            for k,v in vuln.items():
                print(f"{k}:")
                for a in v:
                    print(f"    {a}")
        



class TFTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("tftp")
        self.register_subservice(TFTPBruteSubServiceClass())
