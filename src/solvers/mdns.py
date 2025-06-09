from src.services.mdns import MDNSDiscoverySubServiceClass
from src.solvers.solverclass import BaseSolverClass

class MDNSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("NTP", 17)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "mdns.txt" 

        if not self.hosts:
            return
        if self.is_nv:
            MDNSDiscoverySubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        else:
            MDNSDiscoverySubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
