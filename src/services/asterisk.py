import subprocess
import os
from src.utilities.utilities import error_handler, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class AsteriskVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("-p", "--ports", type=str, default="5030-5080", help="sippts port argument (Default = 5030-5080)")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), ports=args.ports, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        ports = kwargs.get("ports", "5030-5080")
        sippts_output = kwargs.get("sippts_output", "nv-asterisk-data")

        with open("sippts_input.txt", "w") as f:
            for host in hosts:
                f.write(f"{host.ip}\n")

        command = ["sippts", "scan", "-f", "sippts_input.txt", "-r", ports, "-p", "all", "-o", sippts_output]

        subprocess.run(command, text=True, capture_output=True)
            
        with open(sippts_output) as f:
            self.print_output(f.read())
        os.remove(sippts_output)
        os.remove("sippts_input.txt")

class AsteriskServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("asterisk")
        self.register_subservice(AsteriskVersionSubServiceClass())