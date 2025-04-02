from src.services.ftp import FTPAnonSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class FTPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("FTP", 31)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            FTPAnonSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
