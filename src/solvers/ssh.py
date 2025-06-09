from src.services import ssh
from src.services.ssh import SSHAuditSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class SSHAuditSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SSH Service Misconfigurations", 3)
        self.output_filename_for_all = "ssh-audit.txt"
        self.output_png_for_action = "ssh-audit.png"
        self.action_title = "SSHAudit"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        SSHAuditSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        self.create_windowcatcher_action()