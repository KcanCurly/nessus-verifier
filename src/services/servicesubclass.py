from src.utilities.utilities import add_default_parser_arguments, get_hosts_from_file2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass as base_service
from dataclasses import dataclass

class BaseSubServiceClass():
    def __init__(self, command_name: str, help_description: str) -> None:
        self.command_name = command_name
        self.help_description = help_description

    def _set_parent(self, service: base_service):
        self.parent_service = service

    def helper_parse(self, subparsers):
        parser_enum = subparsers.add_parser(self.command_name, help = self.help_description)
        add_default_parser_arguments(parser_enum)
        parser_enum.set_defaults(func=self.console)

    def solve(self, args):
        self.console(args)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, outout=args.output)

    def nv(self, hosts, **kwargs):
        self.threads = kwargs.get("threads", DEFAULT_THREAD)
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.errors = kwargs.get("errors", DEFAULT_ERRORS)
        self.verbose = kwargs.get("verbose", DEFAULT_VERBOSE)
        self.output = kwargs.get("output", "")

    @error_handler([])
    def print_output(self, message):
        print(message)
        if self.output:
            with open(self.output, "a") as f:
                print(message, file=f)

class ExampleSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("example", "Example")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port    

@dataclass
class NVOptions:
    threads: int = DEFAULT_THREAD
    timeout: int = DEFAULT_TIMEOUT
    errors: int = DEFAULT_ERRORS
    verbose: bool = DEFAULT_VERBOSE
    output: str = ""