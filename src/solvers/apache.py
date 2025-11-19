import os
from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_header_from_url, get_default_context_execution, get_cves, get_poc_cve_github_link
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass, WindowCatcherData

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
        self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Apache Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves = set()

        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output("Detected Apache Versions:")
            for key, value in versions.items():
                cves = []
                if self.print_cve:
                    cves = get_cves(f"cpe:2.3:a:apache:http_server:{key}", cves_to_skip=shodan_cves_to_skip)
                if cves: 
                    self.print_output(f"Apache {key} ({", ".join(cves)}):")
                else: self.print_output(f"Apache {key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()

            if self.print_latest_version:
                latest_versions = self.get_latest_version()
                if latest_versions:
                    self.print_output(f"Latest version for {self.eol_product_name}")
                    for version in latest_versions:
                        self.print_output(version)

            for cve in all_cves:
                links = get_poc_cve_github_link(cve)
                if links:
                    self.print_output(f"{cve}:")
                    for link in links:
                        self.print_output(link)
                    
    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"Apache/(.*)"
        header = get_header_from_url(host, "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)
