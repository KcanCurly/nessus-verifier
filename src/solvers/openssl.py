from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_cves, get_header_from_url, get_default_context_execution
import re
from src.solvers.solverclass import BaseSolverClass

class OpenSSLSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("OpenSSL", 32)
        self.output_filename_for_all = "old-openssl.txt"
        self.output_png_for_action = "old-openssl.png"
        self.action_title = "OldOpenssl"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        else:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("OpenSSL Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))

            self.print_output("Detected OpenSSL versions:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:openssl:openssl:{key}")
                if cves: 
                    self.print_output(f"OpenSSL {key} ({", ".join(cves)})")
                else: 
                    self.print_output(f"OpenSSL {key}")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
                
    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"OpenSSL\/(\S+)"
        header = get_header_from_url(str(host), "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                return Version_Vuln_Host_Data(host, m.group(1))