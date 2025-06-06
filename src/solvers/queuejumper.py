import subprocess
import re
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler

class QueueJumperSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Queuejumper", 28)

    @error_handler([])
    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        print("Running metasploit cve_2023_21554_queuejumper module, there will be no progression bar")
        hosts = [entry.ip for entry in self.hosts]
        result = ", ".join(hosts)
        vuln = []
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/msmq/cve_2023_21554_queuejumper; set RHOSTS {result}; set ConnectTimeout {args.threads}; run; exit"]
        try:
            result = subprocess.run(command, text=True, capture_output=True)
            if args.verbose:
                print("stdout:", result.stdout)
                print("stderr:", result.stderr)
            pattern = r"\[\+\] (.*)\s+ - MSMQ vulnerable to CVE-2023-21554"
            matches = re.findall(pattern, result.stdout)
            for m in matches:
                vuln.append(m)
                    
        except Exception as e: 
            self._print_exception(e)
        
        if vuln:
            print("Vulnerable to CVE-2023-21554 (QueueJumper):")
            for v in vuln:
                print(f"    {v}")

