from src.services.idrac import IDRACVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class IDRACSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("iDRAC", 19, args)

    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            IDRACVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose)