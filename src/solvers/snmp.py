from src.solvers.solverclass import BaseSolverClass
from src.services.snmp import SNMPDefaultSubServiceClass

class SNMPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SNMP Service Misconfigurations", 6)
        self.output_filename_for_all = "snmp-default.txt"
        self.output_png_for_action = "snmp-default.png"
        self.action_title = "SNMPDefault"

    def solve(self, args):
        self.process_args(args)


        if not self.hosts: 
            return
        SNMPDefaultSubServiceClass().nv(self.hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=self.output)
        self.create_windowcatcher_action()
