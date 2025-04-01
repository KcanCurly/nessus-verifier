import re
from src.utilities.utilities import Host, Version_Vuln_Host_Data, get_url_response, get_default_context_execution
from src.solvers.solverclass import BaseSolverClass

class IBMWebSphereSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("IBM WebSphere Version", 29, args)

    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    
    def solve_version_single(self, host, timeout, errors, verbose):
        r = r"<title>WebSphere Application Server V(.*)</title>"
        liberty = r"<title>WebSphere Liberty (.*)</title>"
        try:
            resp = get_url_response(host)
            if resp:
                m = re.search(r, resp.text)
                if m:
                    version = m.group(1)
                    version = f"WebSphere Application Server {version}"
                    return Version_Vuln_Host_Data(host, version)

                else:
                    m = re.search(liberty, resp.text)
                    if m:
                        version = m.group(1)
                        version = f"WebSphere Liberty {version}"
                        return Version_Vuln_Host_Data(host, version)
        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")
    
    def solve_version(self, hosts, threads: int, timeout: int, errors: bool, verbose: bool):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("IBM WebSphere Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
            
        if len(versions) > 0:
            versions = dict(sorted(versions.items(), reverse=True))
            print("Detected IBM WebSphere Versions:")
            for key, value in versions.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")