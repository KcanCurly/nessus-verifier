from src.services.ssh import SSHVersionSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class OpenSSHSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("OpenSSH Versions", 14)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "openssh.txt" 

        if not self.hosts: 
            return
        if self.is_nv:
            SSHVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        else:
            SSHVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
