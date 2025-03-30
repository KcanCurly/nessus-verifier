from src.services import smb
from src.solvers.solverclass import BaseSolverClass

class SMBSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("SMB Service Misconfigurations", 6, args)

    def solve(self, args):
        if not self.hosts: 
            return
        smb.sign_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)