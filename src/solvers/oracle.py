import re
import subprocess
from src.utilities.utilities import Version_Vuln_Data, error_handler, get_default_context_execution
from src.solvers.solverclass import BaseSolverClass

class OracleSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Oracle Database", 27)
        self.output_filename_for_all = "old-oracle.txt"
        self.output_png_for_action = "old-oracle.png"
        self.action_title = "OldOracle"

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
        results: list[Version_Vuln_Data] = get_default_context_execution("Oracle TNS Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output("Oracle TNS versions detected:")
            for key, value in versions.items():
                self.print_output(f"{key}")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
                
    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        version_regex = r"Version (\d+\.\d+\.\d+\.\d+\.\d+)"
        command = ["tnscmd10g", "version", "-h", host.ip, "-p", host.port]
        c = subprocess.run(command, text=True, capture_output=True)
        
        m = re.search(version_regex, c.stdout)
        if m:
            version = m.group(1)
            return Version_Vuln_Data(host, version)


