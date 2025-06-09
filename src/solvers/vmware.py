from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler, get_cves
import re
import subprocess

class VmwareSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("VMWare Product Versions", 13)
        self.output_filename_for_all = "old-vmware.txt"
        self.output_png_for_action = "old-vmware.png"
        self.action_title = "OldVmware"
        
    @error_handler([])
    def solve(self, args):
        self.process_args(args)

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

        
        if versions:
            self.print_output("Detected Vmware Versions:")
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
                    self.print_output(f"{key} ({", ".join(cves)}):")
                else: 
                    self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"{" " * args.space}{v}")
        self.create_windowcatcher_action()

