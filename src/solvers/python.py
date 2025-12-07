from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_header_from_url, get_default_context_execution, get_poc_cve_github_link
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class PythonSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Python Unsupported Version", 23)
        self.output_filename_for_all = "old-python.txt"
        self.output_png_for_action = "old-python.png"
        self.action_title = "OldPython"
        self.eol_product_name = "python"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        
    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Python Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves =set()
        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output("Detected Python versions:")
            for key, value in versions.items():
                
                if parse(key) < parse("3.9"):
                    self.print_output(f"Python {key} (EOL):")
                else: 
                    self.print_output(f"Python {key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
            for cve in all_cves:
                links = get_poc_cve_github_link(cve)
                if links:
                    self.print_output(f"{cve}:")
                    for link in links:
                        self.print_output(link)
            self.print_latest_versions()



    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        r = r"Python/(.*)"
        header = get_header_from_url(str(host), "Server", timeout=timeout)
        if header:
            m = re.search(r, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)

