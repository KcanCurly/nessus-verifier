from services.apache_tomcat import TomcatVersionSubServiceClass
from utilities.utilities import error_handler
from solvers.solverclass import BaseSolverClass

class TomcatSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Apache Tomcat Version", 10)
        self.output_filename_for_all = "old-tomcat.txt"
        self.output_png_for_action = "old-tomcat.png"
        self.action_title = "OldTomcat"
        self.eol_product_name = "tomcat"
        
    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        TomcatVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose, output=self.output, print_latest_version=args.print_latest_version, print_poc=args.print_poc, print_cve=args.print_cve)
            