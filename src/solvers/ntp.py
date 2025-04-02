from src.services.ntp import NTPMode6SubServiceClass, NTPMonlistSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class NTPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("NTP", 4)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            NTPMode6SubServiceClass().nv(self._get_subhosts("Network Time Protocol (NTP) Mode 6 Scanner"), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            NTPMonlistSubServiceClass().nv(self._get_subhosts("Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS"), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
        else:
            NTPMode6SubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            NTPMonlistSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)