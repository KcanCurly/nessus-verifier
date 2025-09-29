import re
from src.utilities.utilities import Host, Version_Vuln_Host_Data, error_handler, get_cves, get_url_response, get_default_context_execution, get_poc_cve_github_link
from src.solvers.solverclass import BaseSolverClass
from packaging.version import parse

class KibanaSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Kibana", 24)
        self.output_filename_for_all = "kibana.txt"
        self.output_png_for_action = "kibana.png"
        self.action_title = "Kibana"
        self.eol_product_name = "kibana"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.timeout, args.verbose)

    @error_handler(["host"])
    def solve_version_single(self, host: Host, timeout: int, errors: bool, verbose: bool):
        version_regex = r'data="{&quot;version&quot;:&quot;(.*)&quot;,&quot;buildNumber'
        resp = get_url_response(str(host), timeout=timeout)
        if not resp:
            return
        m = re.search(version_regex, resp.text)
        if m:
            return Version_Vuln_Host_Data(host, m.group(1))

    @error_handler([])
    def solve_version(self, hosts: list[Host], threads: int, timeout: int, errors: bool, verbose: bool):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Kibana Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        
        all_cves = set()
        

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )

            self.print_output("Detected Kibana Versions:")
            for key, value in versions.items():
                cves = []
                if self.print_cves:
                    cves = get_cves(f"cpe:2.3:a:elastic:kibana:{key}")
                if cves: 
                    all_cves.update(cves)
                    self.print_output(f"Kibana {key} ({", ".join(cves)}):")
                else: 
                    self.print_output(f"Kibana {key}:")

                for v in value:
                    self.print_output(f"    {v}")

            self.create_windowcatcher_action()

            for cve in all_cves:
                links = get_poc_cve_github_link(cve)
                if links:
                    self.print_output(f"{cve}:")
                    for link in links:
                        self.print_output(link)
            latest_versions = self.get_latest_version()
            if latest_versions:
                self.print_output(f"Latest version for {self.eol_product_name}")
                for version in latest_versions:
                    self.print_output(version)
                
