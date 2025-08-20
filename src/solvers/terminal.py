import subprocess
import re
import os
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler
from src.external.rdpy import RDPConfig, LU_ISSUES



class TerminalSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Terminal Services Misconfigurations", 8)
        self.output_filename_for_all = "terminal.txt"
        self.output_png_for_action = "terminal.png"
        self.action_title = "Terminal"

    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        issue_re = r"\[-\] (.*) has issue (.*)"

        vuln = {}

        print("Running rdp-sec-check.pl, there will be no progression bar")
        for host in self.hosts:
            try:
                rdpc = RDPConfig(host.ip, int(host.port), args.timeout)
                rdpc.run_tests()
                if rdpc.issues:
                    vuln[f"{host.ip}:{host.port}"] = []
                    for i in rdpc.issues:
                        vuln[f"{host.ip}:{host.port}"].append(LU_ISSUES[i])

            except Exception as e: 
                self._print_exception(f"Error for {host}: {e}")
                
        if vuln:
            self.print_output("Terminal Misconfigurations Detected:")
            for key, value in vuln.items():
                self.print_output(f"{key}")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
