from src.services import ssh
from src.services.ssh import SSHAuditSubServiceClass
from src.solvers.solverclass import BaseSolverClass

SSH_AUDIT_FILENAME_FOR_ALL = "ssh-audit.txt"

class SSHAuditSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SSH Service Misconfigurations", 3)
        self.output_filename_for_all = SSH_AUDIT_FILENAME_FOR_ALL

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        SSHAuditSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)