from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_cves, get_header_from_url, get_default_context_execution
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class PHPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("PHP", 21)
        self.output_filename_for_all = "old-php.txt"
        self.output_png_for_action = "old-php.png"
        self.action_title = "OldPHP"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        else:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"PHP\/(\d+\.\d+\.\d+)"
        powered_by = get_header_from_url(str(host), "X-Powered-By")
        if not powered_by: 
            return
        m = re.search(version_regex, powered_by)
        if m:
            ver = m.group(1)
            return Version_Vuln_Host_Data(host, ver)   
        else:
            server = get_header_from_url(str(host), "Server")
            if not server: 
                return
            m = re.search(version_regex, server)
            if m:
                ver = m.group(1)
                return Version_Vuln_Host_Data(host, ver)      

    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("PHP Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output("Detected PHP versions:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:php:php:{key}")
                if cves: 
                    self.print_output(f"PHP/{key} ({", ".join(cves)}):")
                else: 
                    self.print_output(f"PHP/{key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
