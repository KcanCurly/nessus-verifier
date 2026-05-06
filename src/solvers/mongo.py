from src.services import mongodb
from src.solvers.solverclass import BaseSolverClass

class MongoSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("MongoDB", 26)
        self.output_filename_for_all = "mongo.txt"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        m = mongodb.MongoDBServiceClass()
        m.subservices[0].nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output, print_latest_version=not args.no_print_latest_version, print_poc=not args.no_print_poc, print_cve=not args.no_print_cve)