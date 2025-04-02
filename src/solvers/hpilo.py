from src.utilities.utilities import Host, Version_Vuln_Host_Data, get_url_response, get_default_context_execution
from src.solvers.solverclass import BaseSolverClass

class HPiLOSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("HP iLO Version", 34)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)


    def solve_version_single(self, host, timeout, errors, verbose):
        try:
            resp = get_url_response(f"{host}/json/login_session")     
            if not resp:
                return   
            big_version = resp.json()["moniker"]["PRODGEN"]
            version = resp.json()["version"]
            return Version_Vuln_Host_Data(host, f"{big_version} - {version}")
        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")

    def solve_version(self, hosts: list[Host], threads: int, timeout: int, errors, verbose: bool):
        versions: dict[str, set[Host]] = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("HP iLO Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        
        if len(versions) > 0:
            print("Detected HP iLO versions:")
            versions = dict(sorted(versions.items(), reverse=True))
            for key, value in versions.items():
                """
                cves = get_cves(f"cpe:2.3:a:grafana:grafana:{key}")
                if cves: print(f"HP iLO {key} ({", ".join(cves)}):")
                else: print(f"HP iLO {key}:")
                """
                print(f"HP iLO {key}:")
                for v in value:
                    print(f"    {v}")
                