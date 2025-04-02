import re
from src.utilities.utilities import Host, Version_Vuln_Host_Data, get_url_response, get_default_context_execution
from src.solvers.solverclass import BaseSolverClass

class KibanaSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("Kibana", 24, args)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.timeout, args.verbose)


    def solve_version_single(self, host: Host, timeout: int, errors: bool, verbose: bool):
        version_regex = r'data="{&quot;version&quot;:&quot;(.*)&quot;,&quot;buildNumber'
        try:
            resp = get_url_response(str(host), timeout=timeout)
            if not resp:
                return
            m = re.search(version_regex, resp.text)
            if m:
                return Version_Vuln_Host_Data(host, m.group(1))
        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")

    def solve_version(self, hosts: list[Host], threads: int, timeout: int, errors: bool, verbose: bool):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Kibana Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
                    
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            print("Detected Kibana versions:")
            versions = dict(sorted(versions.items(), reverse=True))
            for key, value in versions.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")


