from src.services.nfs import NFSListServiceClass
from src.solvers.solverclass import BaseSolverClass

class NFSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("NFS", 15)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "nfs.txt" 

        if not self.hosts:
            return
        if self.is_nv:
            NFSListServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)

