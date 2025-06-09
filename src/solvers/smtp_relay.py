import tomllib
from src.utilities.utilities import add_default_solver_parser_arguments, add_default_parser_arguments
from src.solvers.solverclass import BaseSolverClass
from src.services.smtp import SMTPOpenRelaySubServiceClass

class SMTPSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("SMTP Open Relay", 2)

    def helper_parse(self, subparser):
        parser_task1 = subparser.add_parser(str(self.id), help="SMTP Open Relay Test")
        add_default_solver_parser_arguments(parser_task1)
        parser_task1.add_argument("target", type=str, help="File name or targets seperated by space")
        parser_task1.add_argument("client1", type=str, help="Client email address 1")
        parser_task1.add_argument("client2", type=str, help="Client email address 2")
        parser_task1.add_argument("in_fake", type=str, help="Fake email address in domain")
        parser_task1.add_argument("out_fake", type=str, help="Fake email address out of domain")
        parser_task1.add_argument("out_real", type=str, help="Real email address out of domain")
        parser_task1.add_argument("temp", type=str, help="Temporary email address")
        parser_task1.add_argument("--subject", type=str, default="Openrelay Test", help="Email subject")
        parser_task1.add_argument("--message", type=str, default="Openrelay test message", help="Email message, this is a template meaning $host would be replaced with the host value")
        parser_task1.add_argument("--confirm", action="store_true", help="Bypass confirm prompt")
        add_default_parser_arguments(parser_task1, False)
        parser_task1.set_defaults(func=self.solve)

    def process_config(self, config: str) -> None:
        try:
            with open(config, "rb") as f:
                config = tomllib.load(f) # type: ignore
                if str(self.id) in config:
                    self.client1 = config[str(self.id)].get("client1", "") # type: ignore
                    self.client2 = config[str(self.id)].get("client2", "") # type: ignore
                    self.in_fake = config[str(self.id)].get("in_fake", "") # type: ignore
                    self.out_fake = config[str(self.id)].get("out_fake", "") # type: ignore
                    self.out_real = config[str(self.id)].get("out_real", "") # type: ignore
                    self.temp = config[str(self.id)].get("temp", "") # type: ignore

        except Exception as e:
            print(f"Error reading config file: {e}")
            return
        
    def get_default_config(self):
        return f"[{self.id}]\nclient1 = example@example.com\nclient2 = example@example.com\nin_fake = example@example.com\nout_fake = example@example.com\nout_real = example@example.com\ntemp = example@example.com\n"
    
    def solve(self, args):
        super().solve(args)
        if not self.hosts: 
            return
        if hasattr(args, "is_all") and args.is_all:
            args.client1 = self.client1
            args.client2 = self.client2
            args.in_fake = self.in_fake
            args.out_fake = self.out_fake
            args.out_real = self.out_real
            args.temp = self.temp
        SMTPOpenRelaySubServiceClass().nv(self.hosts, client1=args.client1, client2=args.client2, in_fake=args.in_fake, out_fake=args.out_fake, temp=args.temp)