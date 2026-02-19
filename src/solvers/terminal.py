import subprocess
import i18n
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler, get_default_context_execution2
import re

class TerminalSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Terminal Services Misconfigurations", 8)
        self.output_filename_for_all = "terminal.txt"
        self.output_png_for_action = "terminal.png"
        self.action_title = "Terminal"

    @error_handler(["host"])
    def solve_single(self, host, timeout, errors, verbose):
        
        result = subprocess.run(
            ["perl", "rdp_check.pl", f"{host.ip}:{host.port}"],
            capture_output=True,
            text=True
        )

        issues = re.findall(r'has issue ([A-Z0-9_]+)', result.stdout)
        if issues:
            return {f"{host.ip}:{host.port}": issues}

    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return

        results = get_default_context_execution2("banner grab", args.threads, self.hosts, self.solve_single, timeout=args.timeout)
                
        if results:
            self.print_output(i18n.t('main.terminal_misconfiguration_title'))
            for key, value in results.items():
                self.print_output(f"{key}")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
