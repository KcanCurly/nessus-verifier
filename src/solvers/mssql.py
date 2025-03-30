from src.services import mssql
from src.solvers.solverclass import BaseSolverClass

class MSSQLSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("MSSQL Version", 16, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            mssql.version_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
