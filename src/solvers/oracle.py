import re
import subprocess
from src.utilities.utilities import Version_Vuln_Data, get_default_context_execution
from src.solvers.solverclass import BaseSolverClass

class OracleSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("Oracle Database", 27, args)

    def solve(self, args):
        if not self.hosts: 
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)
        else:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Data] = get_default_context_execution("Oracle TNS Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if len(versions) > 0:
            versions = dict(sorted(versions.items(), reverse=True))
            print("Oracle TNS versions detected:")
            for key, value in versions.items():
                print(f"{key}")
                for v in value:
                    print(f"    {v}")
                
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"Version (\d+\.\d+\.\d+\.\d+\.\d+)"

        try:
            command = ["tnscmd10g", "version", "-h", host.ip, "-p", host.port]
            c = subprocess.run(command, text=True, capture_output=True)
            
            m = re.search(version_regex, c.stdout)
            if m:
                version = m.group(1)
                return Version_Vuln_Data(host, version)

        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")

