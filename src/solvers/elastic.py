from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_url_response, get_default_context_execution, add_default_solver_parser_arguments, get_cves
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class ElasticsearchSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Elasticsearch", 25)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)


    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        resp = get_url_response(host, timeout=timeout)
        if not resp:
            return
        version = resp.json()['version']['number']
        return Version_Vuln_Host_Data(host, version)

    
    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Elastic Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        
        if len(versions) > 0:       
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            print("Elastic versions detected:")
            for key, value in versions.items():
                cves = get_cves(f"cpe:2.3:a:elastic:elasticsearch:{key}")
                if cves: print(f"Elastic {key} ({", ".join(cves)}):")
                else: print(f"Elastic {key}:")
                for v in value:
                    print(f"    {v}")
    

    