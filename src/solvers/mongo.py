from src.services import mongodb
from src.solvers.solverclass import BaseSolverClass

class MongoSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("MongoDB", 26)

    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "mongo.txt" 

        if not self.hosts:
            return
        if self.is_nv:
            mongodb.MongoDBVersionSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)