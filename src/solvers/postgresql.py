from src.services.postgresql import PSQLDefaultSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class PSQLSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("PostgreSQL", 30, args)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return
        if self.is_nv:
            PSQLDefaultSubServiceClass().nv(self._get_subhosts('PostgreSQL Default Unpassworded Account'), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            PSQLDefaultSubServiceClass().nv(self._get_subhosts('PostgreSQL Empty Password Handling Remote Authentication Bypass'), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
        else:
            PSQLDefaultSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)