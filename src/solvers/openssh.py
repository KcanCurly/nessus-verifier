from src.services import ssh
from src.solvers.solverclass import BaseSolverClass

class OpenSSHSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("OpenSSH Versions", 14, args)

    def solve(self, args):
        if not self.hosts: 
            return
        if self.is_nv:
            ssh.version_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        else:
            ssh.version_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
