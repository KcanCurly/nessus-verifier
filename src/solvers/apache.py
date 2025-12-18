import os

import i18n
from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_header_from_url, get_default_context_execution, get_cves, get_poc_cve_github_link
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass, WindowCatcherData
from src.services.apache_tomcat import TomcatVersionSubServiceClass

shodan_cves_to_skip = ["CVE-2006-20001"]

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
        TomcatVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbos=args.verbose, output=self.output)