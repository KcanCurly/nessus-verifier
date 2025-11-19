from src.services import mongodb
from src.solvers.solverclass import BaseSolverClass

class MongoSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("MongoDB", 26)
        self.output_filename_for_all = "mongo.txt"
        self.output_png_for_action = "old-mongo.png"
        self.action_title = "OldMongo"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        mongodb.MongoDBVersionSubServiceClass().nv(self.hosts, print_cve=args.print_cve, print_latest_version=args.print_latest_version, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        self.create_windowcatcher_action()