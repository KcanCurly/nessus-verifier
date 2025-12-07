from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_cves, get_header_from_url, get_default_context_execution, get_poc_cve_github_link
import re
from src.solvers.solverclass import BaseSolverClass

class OpenSSLSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("OpenSSL", 32)
        self.output_filename_for_all = "old-openssl.txt"
        self.output_png_for_action = "old-openssl.png"
        self.action_title = "OldOpenssl"
        self.eol_product_name = "openssl"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return

        self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)


    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("OpenSSL Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves =set()
        if versions:
            versions = dict(sorted(versions.items(), reverse=True))

            self.print_output("Detected OpenSSL versions:")
            for key, value in versions.items():
                cves = []
                if self.print_cve:
                    cves = get_cves(f"cpe:2.3:a:openssl:openssl:{key}")
                if cves:
                    all_cves.update(cves)
                    self.print_output(f"OpenSSL {key} ({", ".join(cves)})")
                else: 
                    self.print_output(f"OpenSSL {key}")
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
        version_regex = r"OpenSSL\/(\S+)"
        header = get_header_from_url(str(host), "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                return Version_Vuln_Host_Data(host, m.group(1))