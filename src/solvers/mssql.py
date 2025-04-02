from src.services.mssql import MSSQLVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class MSSQLSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("MSSQL Version", 16)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            MSSQLVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
