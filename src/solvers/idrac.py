from src.services.idrac import version_nv
from src.solvers.solverclass import BaseSolverClass

class IDRACSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("iDRAC", 19, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            version_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)