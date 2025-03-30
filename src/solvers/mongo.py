from src.services import mongodb
from src.solvers.solverclass import BaseSolverClass

class MongoSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("MongoDB", 26, args)

    def solve(self, args):
        if not self.hosts:
            return
        if self.is_nv:
            mongodb.version_nv(self.hosts, args.threads, args.timeout, args.errors, args.verbose)