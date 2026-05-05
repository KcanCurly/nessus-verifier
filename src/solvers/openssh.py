from src.services.ssh import SSHVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class OpenSSHSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("OpenSSH Versions", 14)
        self.output_filename_for_all = "old-openssh.txt"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        SSHVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output, print_latest_version=args.print_latest_version, print_poc=args.print_poc, print_cve=args.print_cve)
