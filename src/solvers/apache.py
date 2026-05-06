from src.solvers.solverclass import BaseSolverClass
from src.services.apache import ApacheVersionSubServiceClass

APACHE_FILENAME_FOR_ALL = "old-apache.txt"

class ApacheSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Apache", 11)
        self.output_filename_for_all = APACHE_FILENAME_FOR_ALL
        self.eol_product_name = "apache-http-server"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        ApacheVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose, output=self.output, print_latest_version=not args.no_print_latest_version, print_poc=not args.no_print_poc, print_cve=not args.no_print_cve)