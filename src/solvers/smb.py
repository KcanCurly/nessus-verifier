from src.solvers.solverclass import BaseSolverClass
from src.services.smb import SMBSignSubServiceClass

class SMBSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SMB Service Misconfigurations", 5)
        self.output_filename_for_all = "smb-sign.txt"
        self.output_png_for_action = "smb-sign.png"
        self.action_title = "SMBSign"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        SMBSignSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        self.create_windowcatcher_action()
