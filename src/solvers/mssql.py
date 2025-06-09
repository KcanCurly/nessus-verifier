from src.services.mssql import MSSQLVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class MSSQLSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("MSSQL Version", 16)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "mssql.txt" 

        if not self.hosts:
            return
        if self.is_nv:
            MSSQLVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
