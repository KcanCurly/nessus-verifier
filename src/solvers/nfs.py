from src.services import nfs
from src.solvers.solverclass import BaseSolverClass

class NFSSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("NFS", 15, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            nfs.list_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

