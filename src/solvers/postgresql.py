from src.services.postgresql import PSQLDefaultSubServiceClass
from src.solvers.solverclass import BaseSolverClass

class PSQLSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("PostgreSQL", 30)
        self.output_filename_for_all = "postgresql-unauth.txt"
        self.output_png_for_action = "postgresql-unauth.png"
        self.action_title = "PSQLUnauth"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts: 
            return
        if self.is_nv:
            PSQLDefaultSubServiceClass().nv(self._get_subhosts('PostgreSQL Default Unpassworded Account'), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
            PSQLDefaultSubServiceClass().nv(self._get_subhosts('PostgreSQL Empty Password Handling Remote Authentication Bypass'), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
            self.create_windowcatcher_action()
        else:
            PSQLDefaultSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)