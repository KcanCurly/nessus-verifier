from src.utilities.utilities import Host, Version_Vuln_Host_Data, get_cves, get_url_response, get_default_context_execution
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class JenkinsSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("Jenkins Version", 35, args)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.timeout, args.verbose)

    def solve_version_single(self, host: Host, timeout: int, errors: bool, verbose: bool):
        r = r"Jenkins-Version: (\S+)"
        try:
            resp = get_url_response(host, timeout=timeout)
            if not resp:
                return
            m = re.search(r, resp.text)
            if m: 
                return  Version_Vuln_Host_Data(host, m.group(1))

        except Exception as e:
            self._print_exception(e)

    def solve_version(self, hosts: list[Host], threads: int, timeout: int, errors, verbose):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Jenkins Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
                    
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            print("Detected Jenkins versions:")
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:jenkins:jenkins:{key}")
                if cves: 
                    print(f"Jenkins {key} ({", ".join(cves)}):")
                else: 
                    print(f"Jenkins {key}:")
                for v in value:
                    print(f"    {v}")
                

