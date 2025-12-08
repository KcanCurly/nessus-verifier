import i18n
from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_poc_cve_github_link, get_url_response, get_default_context_execution, get_cves
from src.solvers.solverclass import BaseSolverClass
import re
from packaging.version import parse

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
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Apache Tomcat", args.threads, self.hosts, (self.solve_version_single, args.timeout, args.errors, args.verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves =set()
        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            total_cves = []
            self.print_output(i18n.t('main.version_title', name='Apache Tomcat'))
            for key, value in versions.items():
                cves = []
                if key.startswith("8"): 
                    self.print_output(f"Apache Tomcat {key} (EOL):")
                else:
                    if self.print_cve:
                        cves = get_cves(f"cpe:2.3:a:apache:tomcat:{key}")
                    if cves: 
                        all_cves.update(cves)
                        self.print_output(f"Apache Tomcat {key} ({", ".join(cves)}):")
                    else: 
                        self.print_output(f"Apache Tomcat {key}:")
                    total_cves.extend(cves)
                for v in value:
                    self.print_output(f"    {v}")
                    
            poc_printed = False
            if "CVE-2025-24813" in total_cves:
                if not poc_printed: 
                    self.print_output("\nPOC:")
                    poc_printed = True
                self.print_output("CVE-2025-24813 => https://github.com/absholi7ly/POC-CVE-2025-24813")
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
        r1 = r"Apache Tomcat\/(\d+\.\d+\.\d+)"

        resp = get_url_response(str(host), timeout=timeout)
        m = re.search(r1, resp.text, re.MULTILINE) # type: ignore
        if m: 
            return Version_Vuln_Host_Data(host, m.group(1))
            

        
