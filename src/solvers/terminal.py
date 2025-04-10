import subprocess
import re
import os
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler

class TerminalSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Terminal Services Misconfigurations", 8)

    @error_handler([])
    def solve(self, args):
        super().solve(args)
        if not self.hosts: 
            return
        issue_re = r"\[-\] (.*) has issue (.*)"

        vuln = {}
        
        
        print("Running rdp-sec-check.pl, there will be no progression bar")
        for host in self.hosts:
            try:
                p = os.path.join(os.path.expanduser("~"), "rdp-sec-check", "rdp-sec-check.pl")
                command = ["perl", p, host.ip]
                result = subprocess.run(command, text=True, capture_output=True)
                
                matches = re.findall(issue_re, result.stdout)
                
                for match in matches:
                    if match[0] not in vuln:
                        vuln[match[0]] = []
                    vuln[match[0]].append(match[1])
            except Exception as e: 
                self._print_exception(f"Error for {host}: {e}")
                
        if vuln:
            print("Terminal Misconfigurations Detected:")
            for key, value in vuln.items():
                print(f"{key}")
                for v in value:
                    print(f"    {v}")
