from src.services.mdns import MDNSDiscoverySubServiceClass
from src.solvers.solverclass import BaseSolverClass

class MDNSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("mdns", 17)
        self.output_filename_for_all = "mdns.txt"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        MDNSDiscoverySubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
