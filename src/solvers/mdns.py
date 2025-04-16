from src.services.mdns import MDNSDiscoverySubServiceClass
from src.solvers.solverclass import BaseSolverClass

class MDNSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("NTP", 4)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            MDNSDiscoverySubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
        else:
            MDNSDiscoverySubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
