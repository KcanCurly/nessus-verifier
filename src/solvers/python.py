from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_header_from_url, get_default_context_execution
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class PythonSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Python Unsupported Version", 23)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        
    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Python Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            print("Detected Python versions:")
            for key, value in versions.items():
                if parse(key) < parse("3.9"):
                    print(f"{key} (EOL):")
                else: 
                    print(f"Python {key}:")
                for v in value:
                    print(f"    {v}")



    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        r = r"Python/(.*)"
        header = get_header_from_url(str(host), "Server", timeout=timeout)
        if header:
            m = re.search(r, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)

