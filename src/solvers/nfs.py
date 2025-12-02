from src.services.nfs import NFSListServiceClass
from src.solvers.solverclass import BaseSolverClass

class NFSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("NFS", 15)
        self.output_filename_for_all = "nfs.txt"
        self.output_png_for_action = "nfs.png"
        self.action_title = "NFS"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        NFSListServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        self.create_windowcatcher_action()

