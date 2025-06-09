from src.solvers.solverclass import BaseSolverClass
from src.services.snmp import SNMPDefaultSubServiceClass

class SNMPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SNMP Service Misconfigurations", 6)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "snmp.txt" 

        if not self.hosts: 
            return
        SNMPDefaultSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
