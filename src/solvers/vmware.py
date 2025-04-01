from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import get_cves
import re
import subprocess

class VmwareSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("VMWare Product Versions", 13, args)
        
    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        r = r"\[\+\] (.*) - Identified (.*)"
        versions = {}

        result = ", ".join(h.ip for h in self.hosts)
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS {result}; set ConnectTimeout {args.timeout}; set THREADS {args.threads}; run; exit"]
        try:
            result = subprocess.run(command, text=True, capture_output=True)
            
            matches = re.findall(r, result.stdout)
            for m in matches:
                if m[1] not in versions:
                    versions[m[1]] = []
                versions[m[1]].append(f"{m[0]}")
                    
        except Exception as e:
            self._print_exception(e)

        
        if len(versions) > 0:
            
            print("Detected Vmware Versions:")
            for key, value in versions.items():
                cves = []
                if "esxi" in key.lower(): 
                    r = r"VMware ESXi (\d+\.\d+\.\d+)"
                    m = re.search(r, key)
                    if m: 
                        cves = get_cves(f"cpe:2.3:o:vmware:esxi:{m.group(1)}")
                if "vcenter server" in key.lower(): 
                    r = r"VMware vCenter Server (\d+\.\d+\.\d+)"
                    m = re.search(r, key)
                    if m: 
                        cves = get_cves(f"cpe:2.3:a:vmware:vcenter_server:{m.group(1)}")
                        
                if cves: 
                    print(f"{key} ({", ".join(cves)}):")
                else: 
                    print(f"{key}:")
                for v in value:
                    print(f"    {v}")

