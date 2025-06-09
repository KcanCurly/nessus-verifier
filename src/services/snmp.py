import subprocess
import re
from src.utilities.utilities import error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class SNMPDefaultSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("default", "Checks if default public/private community string is used")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        print("Running metasploit snmp_login module, there will be no progression bar")
        ips = ", ".join(host.ip for host in hosts)

        vuln = {} 
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/snmp/snmp_login; set RHOSTS {ips}; set ConnectTimeout {self.timeout}; set THREADS {self.threads}; run; exit"]
        try:
            result = subprocess.run(command, text=True, capture_output=True)
            if self.verbose:
                print("stdout:", result.stdout)
                print("stderr:", result.stderr)
            pattern = r"\[\+\] (.*) - Login Successful: (.*);.*: (.*)"
            matches = re.findall(pattern, result.stdout)
            for m in matches:
                if m[0] not in vuln:
                    vuln[m[0]] = []
                vuln[m[0]].append(f"{m[1]} - {m[2]}")
                    
        except Exception as e:
            if self.errors: print(f"Error: {e}")
        
        if vuln:
            self.print_output("SNMP community strings were found:")
            for k,v in vuln.items():
                self.print_output(k)
                for a in v:
                    self.print_output(f"    {a}")



class SNMPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("snmp")
        self.register_subservice(SNMPDefaultSubServiceClass())