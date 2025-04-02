from src.utilities.utilities import Version_Vuln_Host_Data, get_cves, get_header_from_url, get_default_context_execution
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class NginxSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Nginx Version", 12)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"nginx/(.*)"
        try:
            header = get_header_from_url(str(host), "Server", timeout, errors, verbose)
            if header:
                m = re.search(version_regex, header)
                if m:
                    m = m.group(1)
                    if " " in m:
                        m = m.split()[0]
                    return Version_Vuln_Host_Data(host, m)

        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")
        
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Nginx Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            print("Detected Nginx Versions:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:f5:nginx_open_source:{key}")
                if not cves:
                    cves = get_cves(f"cpe:2.3:a:f5:nginx:{key}")
                if cves: 
                    print(f"Nginx {key} ({", ".join(cves)}):")
                else: 
                    print(f"Nginx {key}:")
                for v in value:
                    print(f"    {v}")
