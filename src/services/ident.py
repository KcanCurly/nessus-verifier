import subprocess
import re
from src.utilities.utilities import error_handler, get_hosts_from_file2, add_default_parser_arguments
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc

class IdentUsersSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("users", "Enumerates Users")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("-p", "--ports", nargs="+", default=["22", "80", "113", "443"], help="Ports to enumerate")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), ports=args.ports, threads=args.threads, timeout=args.timeout, 
                        errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        ports = kwargs.get("ports", [])

        print("Running ident-user-enum command, there will be no progression bar")
        vuln = {}

        for host in hosts:
            try:
                command = ["ident-user-enum", host.ip, *ports]
                result = subprocess.run(command, text=True, capture_output=True)
                pattern = r"(.*):(.*) (.*)"
                matches = re.findall(pattern, result.stdout)

                for m in matches:
                    if m[0] not in vuln:
                        vuln[m[0]] = []
                    vuln[m[0]].append(f"{m[1]} - {m[2]}")
                
            except Exception as e:
                if self.errors == 1: 
                    print(f"Error for {host}: {e}")
                if self.errors == 2:
                    print(f"Error for {host}: {e}")
                    print_exc()
        
        if vuln:
            self.print_output("Ident service user enumeration:")
            for k,v in vuln.items():
                self.print_output(f"    {k}:113 - {", ".join(v)}")

class IdentServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ident")
        self.register_subservice(IdentUsersSubServiceClass())