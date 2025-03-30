from src.services.ftp import anon_nv
from src.solvers.solverclass import BaseSolverClass

class FTPSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("FTP", 31, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            anon_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
