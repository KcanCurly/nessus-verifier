import re
from src.utilities.utilities import Host, Version_Vuln_Host_Data, error_handler, get_url_response, get_default_context_execution
from src.solvers.solverclass import BaseSolverClass

class IBMWebSphereSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("IBM WebSphere Version", 29)
        self.output_filename_for_all = "ibmwebsphere.txt"
        self.output_png_for_action = "old-ibmwebsphere.png"
        self.action_title = "OldIbmwebsphere"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)

    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        r = r"<title>WebSphere Application Server V(.*)</title>"
        liberty = r"<title>WebSphere Liberty (.*)</title>"
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

    @error_handler([])
    def solve_version(self, hosts, threads: int, timeout: int, errors: bool, verbose: bool):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("IBM WebSphere Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
            
        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output("Detected IBM WebSphere Versions:")
            for key, value in versions.items():
                f"cpe:2.3:a:ibm:websphere_application_server:{key}:*:*:*:liberty"
                f"cpe:2.3:a:ibm:websphere_application_server:{key}"
                self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()