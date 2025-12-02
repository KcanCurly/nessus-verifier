from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_cves, get_header_from_url, get_default_context_execution, get_poc_cve_github_link
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class NginxSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Nginx Version", 12)
        self.output_filename_for_all = "nginx.txt"
        self.output_png_for_action = "nginx.png"
        self.action_title = "Nginx"
        self.eol_product_name = "nginx"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"nginx/(.*)"
        header = get_header_from_url(str(host), "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)


    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Nginx Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves =set()
        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output("Detected Nginx Versions:")
            for key, value in versions.items():
                cves = []
                if self.print_cve:
                    cves = get_cves(f"cpe:2.3:a:f5:nginx_open_source:{key}")
                    if not cves:
                        cves = get_cves(f"cpe:2.3:a:f5:nginx:{key}")
                if cves:
                    all_cves.update(cves)
                    self.print_output(f"Nginx {key} ({", ".join(cves)}):")
                else: 
                    self.print_output(f"Nginx {key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()

            for cve in all_cves:
                links = get_poc_cve_github_link(cve)
                if links:
                    self.print_output(f"{cve}:")
                    for link in links:
                        self.print_output(link)
            if self.print_latest_version:
                latest_versions = self.get_latest_version()
                if latest_versions:
                    self.print_output(f"Latest version for {self.eol_product_name}")
                    for version in latest_versions:
                        self.print_output(version)