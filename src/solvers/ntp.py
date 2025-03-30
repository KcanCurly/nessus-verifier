from src.services import ntp
from src.solvers.solverclass import BaseSolverClass

class NTPSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("NTP", 4, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            ntp.mode6_nv(self._get_subhosts("Network Time Protocol (NTP) Mode 6 Scanner"), args.threads, args.timeout, args.errors, args.verbose)
            ntp.monlist_nv(self._get_subhosts("Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS"), args.threads, args.timeout, args.errors, args.verbose)
        else:
            ntp.mode6_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
            ntp.monlist_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)