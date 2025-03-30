from src.services.postgresql import unpassworded_nv
from src.solvers.solverclass import BaseSolverClass

class PSQLSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("PostgreSQL", 30, args)

    def solve(self, args):
        if not self.hosts: 
            return
        if self.is_nv:
            unpassworded_nv(self._get_subhosts('PostgreSQL Default Unpassworded Account'), args.threads, args.timeout, args.errors, args.verbose)
            unpassworded_nv(self._get_subhosts('PostgreSQL Empty Password Handling Remote Authentication Bypass'), args.threads, args.timeout, args.errors, args.verbose)
        else:
            unpassworded_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)