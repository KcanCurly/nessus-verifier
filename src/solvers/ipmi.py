import subprocess
import re
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler

class IPMISolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("IPMI", 20)

    @error_handler([])
    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            r = r"[\+] (.*) - IPMI - Hash found: (.*)"
            r1 =  r"[\+] (.*) - IPMI - Hash for user '(.*)' matches password '(.*)'"
            print("Running metasploit ipmi dumphashes module, there will be no progression bar")
            hashes = {}
            creds = {}
            
            
            result = ", ".join(h.ip for h in self.hosts)
            command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {result}; set ConnectTimeout {args.timeout}; set THREADS {args.threads}; run; exit"]
            try:
                result = subprocess.run(command, text=True, capture_output=True)
                
                matches = re.findall(r, result.stdout)
                for m in matches:
                    if m[0] not in hashes:
                        hashes[m[0]] = []
                    hashes[m[0]].append(f"{m[1]}")
                    
                matches = re.findall(r1, result.stdout)
                for m in matches:
                    if m[0] not in hashes:
                        creds[m[0]] = []
                    creds[m[0]].append(f"{m[1]}:{m[2]}")
                        
            except Exception as e:
                self._print_exception(e)
            
            if len(hashes) > 0:
                print("IPMI hashes dumped:")
                for key, value in hashes.items():
                    print(f"{key}:")
                    for v in value:
                        print(f"    {v}")

            if len(creds) > 0:
                print("IPMI Creds found:")
                for key, value in creds.items():
                    print(f"{key}:")
                    for v in value:
                        print(f"    {v}")