from src.services import snmp
from src.solvers.solverclass import BaseSolverClass

class SNMPSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("SNMP Service Misconfigurations", 6, args)

    def solve(self, args):
        if not self.hosts: 
            return
        snmp.default_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
