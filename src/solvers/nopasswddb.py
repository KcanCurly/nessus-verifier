from src.utilities.utilities import Host, get_default_context_execution, get_url_response
from src.services import mongodb
from src.solvers.solverclass import BaseSolverClass
from src.services.postgresql import PSQLDefaultSubServiceClass

class NoPasswordDBSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("Database usage without password", 9, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            mongodb.unauth_nv(self._get_subhosts("MongoDB Service Without Authentication Detection"), args.threads, args.timeout, args.errors, args.verbose)
            PSQLDefaultSubServiceClass().nv(self._get_subhosts("PostgreSQL Default Unpassworded Account"), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            self.solve_elastic_version(self._get_subhosts("Elasticsearch Unrestricted Access Information Disclosure"), args.threads, args.timeout, args.errors, args.verbose)
            

    def solve_elastic_version_single(self, host, timeout, errors, verbose):
        try:
            resp = get_url_response(f"{str(host)}/*", timeout=timeout)
            if not resp:
                return
            if resp.status_code in [200]:
                return host
        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")
        
    def solve_elastic_version(self, hosts, threads, timeout, errors, verbose):
        results: list[Host] = get_default_context_execution("Elasticsearch Unrestricted Access Information Disclosure", threads, hosts, (self.solve_elastic_version_single, timeout, errors, verbose))

        if results:
            print("Elastic Unrestricted Access:")
            for r in results:
                print(f"    {r}")