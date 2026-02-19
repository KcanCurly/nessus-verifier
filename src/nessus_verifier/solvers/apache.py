from solvers.solverclass import BaseSolverClass, WindowCatcherData
from services.apache import ApacheVersionSubServiceClass

class ApacheVersionWindowCatcherData(WindowCatcherData):
    def __init__(self, name, code, output) -> None:
        super().__init__(name, code, output)

class ApacheSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Apache", 11)
        self.output_filename_for_all = "apache.txt"
        self.output_png_for_action = "old-apache.png"
        self.action_title = "Apache"
        self.eol_product_name = "apache-http-server"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        ApacheVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose, output=self.output, print_latest_version=args.print_latest_version, print_poc=args.print_poc, print_cve=args.print_cve)