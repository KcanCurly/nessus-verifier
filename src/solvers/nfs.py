from src.services.nfs import NTPListServiceClass
from src.solvers.solverclass import BaseSolverClass

class NFSSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("NFS", 15, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            NTPListServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

