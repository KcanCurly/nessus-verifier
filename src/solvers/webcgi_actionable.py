from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_poc_cve_github_link, get_url_response, get_default_context_execution, get_cves
from src.solvers.solverclass import BaseSolverClass
import re
from packaging.version import parse

class WebCGIActionableSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Web/CGI Actionable", 34)

    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        browsable_hosts = self._get_subhosts("MongoDB Service Without Authentication Detection")