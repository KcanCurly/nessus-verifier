from src.services import ssh
from src.services.ssh import SSHAuditSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class SSHAuditSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SSH Service Misconfigurations", 3)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "ssh.txt" 

        if not self.hosts: 
            return
        SSHAuditSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
