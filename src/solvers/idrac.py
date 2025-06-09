from src.services.idrac import IDRACVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class IDRACSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("iDRAC", 19)
        self.output_filename_for_all = "idrac.txt"
        self.output_png_for_action = "old-idrac.png"
        self.action_title = "OldIdrac"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        if self.is_nv:
            IDRACVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose, output=self.output)
            self.create_windowcatcher_action()