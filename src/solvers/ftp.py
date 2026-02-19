from src.services.ftp import FTPAnonSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class FTPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("FTP", 31)
        self.output_filename_for_all = "ftp-anon.txt"
        self.output_png_for_action = "ftp-anon.png"
        self.action_title = "FtpAnon"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        FTPAnonSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        self.create_windowcatcher_action()
