from src.services.ssh import SSHVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class OpenSSHSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("OpenSSH Versions", 14, args)

    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        if self.is_nv:
            SSHVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
        else:
            SSHVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
