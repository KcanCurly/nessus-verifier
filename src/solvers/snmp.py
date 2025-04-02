from src.solvers.solverclass import BaseSolverClass
from src.services.snmp import SNMPDefaultSubServiceClass

class SNMPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SNMP Service Misconfigurations", 6)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        SNMPDefaultSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
