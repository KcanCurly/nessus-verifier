from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_poc_cve_github_link, get_url_response, get_default_context_execution, get_cves
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class GrafanaSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Grafana", 22)
        self.output_filename_for_all = "grafana.txt"
        self.output_png_for_action = "old-grafana.png"
        self.action_title = "OldGrafana"
        self.eol_product_name = "grafana"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
    
    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r'Grafana v(.*) \('
        resp = get_url_response(host, timeout=timeout)
        if not resp: 
            return
        m = re.search(version_regex, resp.text)
        if m:
            version = m.group(1)
        return Version_Vuln_Host_Data(host, version)


    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Grafana Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        versions = {}
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves = set()

        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output("Detected Grafana Versions:")
            for key, value in versions.items():
                cves = []
                if self.print_cve:
                    cves = get_cves(f"cpe:2.3:a:grafana:grafana:{key}")
                if cves: 
                    all_cves.update(cves)
                    self.print_output(f"Grafana {key} ({", ".join(cves)}):")
                else: self.print_output(f"Grafana {key}:")
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

