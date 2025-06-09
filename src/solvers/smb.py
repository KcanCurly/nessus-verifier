from src.solvers.solverclass import BaseSolverClass
from src.services.smb import SMBSignSubServiceClass

class SMBSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SMB Service Misconfigurations", 5)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "smb.txt"
             
        if not self.hosts: 
            return
        SMBSignSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
