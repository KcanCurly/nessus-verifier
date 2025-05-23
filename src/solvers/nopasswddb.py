from src.utilities.utilities import Host, error_handler, get_default_context_execution, get_url_response
from src.services import mongodb, postgresql, redis
from src.solvers.solverclass import BaseSolverClass

class NoPasswordDBSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Database usage without password", 9)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            mongodb.MongoDBUnauthSubServiceClass().nv(self._get_subhosts("MongoDB Service Without Authentication Detection"), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            postgresql.PSQLDefaultSubServiceClass().nv(self._get_subhosts("PostgreSQL Default Unpassworded Account"), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            redis.RedisUnauthSubServiceClass().nv(self._get_subhosts("Redis Server Unprotected by Password Authentication"), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            self.solve_elastic_version(self._get_subhosts("Elasticsearch Unrestricted Access Information Disclosure"), args.threads, args.timeout, args.errors, args.verbose)
            
    @error_handler(["host"])
    def solve_elastic_version_single(self, host, timeout, errors, verbose):
        resp = get_url_response(f"{str(host)}/*", timeout=timeout)
        if not resp:
            return
        if resp.status_code in [200]:
            return host

        
    @error_handler([])
    def solve_elastic_version(self, hosts, threads, timeout, errors, verbose):
        results: list[Host] = get_default_context_execution("Elasticsearch Unrestricted Access Information Disclosure", threads, hosts, (self.solve_elastic_version_single, timeout, errors, verbose))

        if results:
            print("Elastic Unrestricted Access:")
            for r in results:
                print(f"    {r}")