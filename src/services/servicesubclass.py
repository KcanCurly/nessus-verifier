from src.services.serviceclass import BaseServiceClass
from src.utilities.utilities import add_default_parser_arguments, get_hosts_from_file

class BaseSubServiceClass():
    def __init__(self, command_name: str, help_description: str) -> None:
        self.command_name = command_name
        self.help_description = help_description

    def _set_parent(self, service: BaseServiceClass):
        self.parent_service = service

    def helper_parse(self, subparsers):
        parser_enum = subparsers.add_parser(self.command_name, self.help_description)
        add_default_parser_arguments(parser_enum)
        parser_enum.set_defaults(func=self.console)

    def solve(self, args):
        self.console(args)

    def console(self, args):
        self.nv(get_hosts_from_file(args.target, False), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

    def nv(self, hosts, **kwargs):
        print(f"Have not yet implemented nv for {self.command_name} for parent {self.parent_service.name}")