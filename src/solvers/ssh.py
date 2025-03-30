from src.services import ssh
from src.solvers.solverclass import BaseSolverClass

class SSHAuditSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("SSH Service Misconfigurations", 3, args)

    def solve(self, args):
        if not self.hosts: 
            return
        ssh.audit_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
