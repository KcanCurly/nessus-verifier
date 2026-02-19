import subprocess
import re
from src.utilities.utilities import error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class FingerUserenumSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("userenum", "Enumerates users")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        result = ", ".join(host.ip for host in hosts)

        vuln = {}
        try:
            command = ["msfconsole", "-q", "-x", f"color false; use scanner/finger/finger_users; set RHOSTS {result}; run; exit"]
            result = subprocess.run(command, text=True, capture_output=True)
            pattern = r"- (.*) Users found: (.*)"
            matches = re.findall(pattern, result.stdout)

            for m in matches:
                if m[0] not in vuln:
                    vuln[m[0]] = []
                vuln[m[0]].append(m[1])
                
        except Exception as e: print(e)
        
        if vuln:
            self.print_output("Finger service user enumeration:")
            for k,v in vuln.items():
                self.print_output(f"    {k}:79 - {", ".join(v)}")

class FingerServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("finger")
        self.register_subservice(FingerUserenumSubServiceClass())