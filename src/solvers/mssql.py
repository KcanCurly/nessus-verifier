from src.services.mssql import MSSQLVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class MSSQLSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("MSSQL Version", 16)
        self.output_filename_for_all = "mssql.txt"
        self.output_png_for_action = "mssql.png"
        self.action_title = "MSSQL"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        MSSQLVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output, print_latest_version=args.print_latest_version, print_pocs=args.print_pocs, print_cve=args.print_cve)
        self.create_windowcatcher_action()
