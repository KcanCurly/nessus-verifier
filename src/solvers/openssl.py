from src.utilities.utilities import Version_Vuln_Host_Data, get_cves, get_header_from_url, get_default_context_execution
import re
from src.solvers.solverclass import BaseSolverClass

class OpenSSLSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("OpenSSL", 32, args)

    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        else:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    def solve_version(self,hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("OpenSSL Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            versions = dict(sorted(versions.items(), reverse=True))

            print("Detected OpenSSL versions:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:openssl:openssl:{key}")
                if cves: 
                    print(f"OpenSSL {key} ({", ".join(cves)})")
                else: 
                    print(f"OpenSSL {key}")
                for v in value:
                    print(f"    {v}")
                
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"OpenSSL\/(\S+)"
        try:
            header = get_header_from_url(str(host), "Server", timeout, errors, verbose)
            if header:
                m = re.search(version_regex, header)
                if m:
                    return Version_Vuln_Host_Data(host, m.group(1))

        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")