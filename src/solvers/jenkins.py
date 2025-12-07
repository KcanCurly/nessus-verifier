from src.utilities.utilities import Host, Version_Vuln_Host_Data, error_handler, get_cves, get_poc_cve_github_link, get_url_response, get_default_context_execution, get_header_from_url
import re
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class JenkinsSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Jenkins Version", 35)
        self.output_filename_for_all = "jenkins.txt"
        self.output_png_for_action = "jenkins.png"
        self.action_title = "Jenkins"
        self.eol_product_name = "jenkins"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        self.solve_version(self.hosts, args.threads, args.timeout, args.timeout, args.verbose)

    @error_handler(["host"])
    def solve_version_single(self, host: Host, timeout: int, errors: bool, verbose: bool):
        r = r"Jenkins-Version: (\S+)"
        resp = get_url_response(host, timeout=timeout)

        m = re.search(r, resp.text) # type: ignore
        if m: 
            return Version_Vuln_Host_Data(host, m.group(1))
        else:
            z = get_header_from_url(host, "X-Jenkins", timeout=timeout, errors=errors, verbose=verbose)
            if z: return Version_Vuln_Host_Data(host, z)


    @error_handler([])
    def solve_version(self, hosts: list[Host], threads: int, timeout: int, errors, verbose):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Jenkins Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        all_cves = set()
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            self.print_output("Detected Jenkins versions:")
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            for key, value in versions.items():
                cves = []
                if compare_versions(key, "2.492") == -1:
                    self.print_output(f"Jenkins {key} (EOL):")
                else:
                    if self.print_cve:
                        cves = get_cves(f"cpe:2.3:a:jenkins:jenkins:{key}")
                    if cves: 
                        self.print_output(f"Jenkins {key} ({", ".join(cves)}):")
                    else: 
                        self.print_output(f"Jenkins {key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
            for cve in all_cves:
                links = get_poc_cve_github_link(cve)
                if links:
                    self.print_output(f"{cve}:")
                    for link in links:
                        self.print_output(link)
            self.print_latest_versions()

                

def normalize_version(v, max_parts=3):
    """Turn version string into list of ints, filling with zeros."""
    return [int(x) for x in v.split('.')] + [0] * (max_parts - v.count('.') - 1)

def compare_versions(v1, v2):
    """Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
    n1 = normalize_version(v1)
    n2 = normalize_version(v2)
    if n1 > n2:
        return 1
    elif n1 < n2:
        return -1
    return 0
