import subprocess
import re
from src.utilities.utilities import error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class SNMPDefaultSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("default", "Checks if default public/private community string is used")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        print("Running metasploit snmp_login module, there will be no progression bar")
        result = ", ".join(host.ip for host in hosts)

        vuln = {} 
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/snmp/snmp_login; set RHOSTS {result}; set ConnectTimeout {timeout}; set THREADS {threads}; run; exit"]
        try:
            result = subprocess.run(command, text=True, capture_output=True)
            if verbose:
                print("stdout:", result.stdout)
                print("stderr:", result.stderr)
            pattern = r"\[\+\] (.*) - Login Successful: (.*);.*: (.*)"
            matches = re.findall(pattern, result.stdout)
            for m in matches:
                if m[0] not in vuln:
                    vuln[m[0]] = []
                vuln[m[0]].append(f"{m[1]} - {m[2]}")
                    
        except Exception as e:
            if errors: print(f"Error: {e}")
        
        if len(vuln) > 0:
            print("SNMP community strings were found:")
            for k,v in vuln.items():
                print(k)
                for a in v:
                    print(f"    {a}")



class SNMPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("snmp")
        self.register_subservice(SNMPDefaultSubServiceClass())