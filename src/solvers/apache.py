from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_header_from_url, add_default_parser_arguments, get_default_context_execution, add_default_solver_parser_arguments, get_cves
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

shodan_cves_to_skip = ["CVE-2006-20001"]

class ApacheSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Apache", 11)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)


    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Apache Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            print("Detected Apache Versions:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:apache:http_server:{key}", cves_to_skip=shodan_cves_to_skip)
                if cves: print(f"Apache/{key} ({", ".join(cves)}):")
                else: print(f"Apache/{key}:")
                for v in value:
                    print(f"    {v}")
                    
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
