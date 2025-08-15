import re
from src.utilities.utilities import Host, Version_Vuln_Host_Data, error_handler, get_cves, get_url_response, get_default_context_execution, get_latest_version
from src.solvers.solverclass import BaseSolverClass
from packaging.version import parse

class KibanaSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Kibana", 24)
        self.output_filename_for_all = "kibana.txt"
        self.output_png_for_action = "kibana.png"
        self.action_title = "Kibana"

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
        
        all_cves =set()

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            total_cves = []
            self.print_output("Detected Kibana Versions:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:elastic:kibana:{key}")
                for cve in cves:
                    all_cves.add(cve)
                if cves: 
                    self.print_output(f"Kibana {key} ({", ".join(cves)}):")
                else: 
                    self.print_output(f"Kibana {key}:")
                total_cves.extend(cves)
                for v in value:
                    self.print_output(f"    {v}")
            get_latest_version("kibana")
            self.create_windowcatcher_action()

        public_exploit_written = False
        if all_cves:
            for cve in all_cves:
                if cve == "CVE-2019-7609":
                    if not public_exploit_written:
                        self.print_output("Public exploits available:")
                    self.print_output("[RCE, Exploit, Reverse Shell] - CVE-2019-7609 - https://github.com/LandGrey/CVE-2019-7609")
                if cve == "CVE-2025-25014":
                    if not public_exploit_written:
                        self.print_output("Public exploits available:")
                    self.print_output("[RCE, Authenticated, Scanner] - CVE-2025-25014 - https://github.com/B1ack4sh/Blackash-CVE-2025-25014")
                if cve == "CVE-2024-23443":
                    if not public_exploit_written:
                        self.print_output("Public exploits available:")
                    self.print_output("[DoS, Authenticated, Exploit] - CVE-2024-23443 - https://github.com/zhazhalove/osquery_cve-2024-23443")
                if cve == "CVE-2019-7616":
                    if not public_exploit_written:
                        self.print_output("Public exploits available:")
                    self.print_output("[SSRF, Exploit] - CVE-2019-7616 - https://github.com/random-robbie/CVE-2019-7616")
                if cve == "CVE-2018-17246":
                    if not public_exploit_written:
                        self.print_output("Public exploits available:")
                    self.print_output("[LFI, Manual Exploit] - CVE-2018-17246 - https://github.com//mpgn//CVE-2018-17246")
                
