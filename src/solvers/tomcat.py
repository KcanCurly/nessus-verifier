from src.services.apache_tomcat import TomcatVersionSubServiceClass
from src.utilities.utilities import error_handler
from src.solvers.solverclass import BaseSolverClass

class TomcatSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Apache Tomcat Version", 10)
        self.output_filename_for_all = "old-tomcat.txt"
        self.eol_product_name = "tomcat"
        
    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        TomcatVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose, output=self.output, print_latest_version=not args.no_print_latest_version, print_poc=not args.no_print_poc, print_cve=not args.no_print_cve)
            