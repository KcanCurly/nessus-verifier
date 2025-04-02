from src.services.nfs import NFSListServiceClass
from src.solvers.solverclass import BaseSolverClass

class NFSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("NFS", 15)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            NFSListServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

