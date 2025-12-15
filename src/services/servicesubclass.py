import threading
from typing import Tuple

import i18n
from src.utilities import utilities
from src.utilities.utilities import add_default_serviceclass_arguments, add_default_version_subservice_arguments, get_cves, get_hosts_from_file2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass as base_service
from dataclasses import dataclass

lock = threading.Lock()


class BaseSubServiceClass():
    def __init__(self, command_name: str, help_description: str) -> None:
        self.command_name = command_name
        self.help_description = help_description

    def _set_parent(self, service: base_service):
        self.parent_service = service

    def helper_parse(self, subparsers):
        parser_enum = subparsers.add_parser(self.command_name, help = self.help_description)
        add_default_serviceclass_arguments(parser_enum)
        parser_enum.set_defaults(func=self.console)

    def solve(self, args):
        self.console(args)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), space=args.space, print_cve=args.print_cve, print_latest_version=args.print_latest_version, print_poc=args.print_poc, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=args.output)

    def nv(self, hosts, **kwargs):
        kwargs = kwargs.get("kwargs", {})
        self.threads = kwargs.get("threads", DEFAULT_THREAD)
        self.timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        self.errors = kwargs.get("errors", DEFAULT_ERRORS)
        self.verbose = kwargs.get("verbose", DEFAULT_VERBOSE)
        self.output = kwargs.get("output", "")
        self.should_print_cves = kwargs.get("print_cve", False)
        self.should_print_latest_version = kwargs.get("print_latest_version", False)
        self.should_print_poc = kwargs.get("print_poc", False)
        self.space = kwargs.get("space")

    def print_latest_versions(self, product_code, product_name):
        if self.should_print_latest_version:
            lv = utilities.get_latest_version(product_code, True)
            if lv:
                self.print_output(i18n.t('main.latest_version_title', name=product_name))
                self.print_output(', '.join(lv or []))

    def print_pocs(self, cve_list):
        if self.should_print_poc and cve_list:
            pocs = utilities.get_poc_from_cves(cve_list)
            if pocs:
                self.print_output(i18n.t('main.poc_title'))
                
                for cve, poc_list in pocs.items():
                    self.print_output(f"{cve}:")
                    for poc in poc_list:
                        self.print_output(f"{poc}")

    @error_handler([])
    def print_output(self, message, normal_print = True):
        if normal_print:
            print(message)
        if self.output:
            with lock:
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

class VersionSubService(BaseSubServiceClass):
    def __init__(self, command_name: str, help_description: str, products: list[tuple[str, str]]) -> None:
        super().__init__(command_name, help_description)
        self.products = products
        self.cves = set()

    def helper_parse(self, subparsers):
        parser_enum = subparsers.add_parser(self.command_name, help = self.help_description)
        add_default_version_subservice_arguments(parser_enum)
        parser_enum.set_defaults(func=self.console)

    def print_latest_versions(self):
        if self.should_print_latest_version and self.products:
            for name, code in self.products:
                lv = utilities.get_latest_version(code, True)
                if lv:
                    self.print_output(i18n.t('main.latest_version_title', name=name))
                    self.print_output(', '.join(lv or []))

    def print_pocs(self):
        if self.should_print_poc and self.cves:
            pocs = utilities.get_poc_from_cves(self.cves)
            if pocs:
                self.print_output(i18n.t('main.poc_title'))
                for cve, poc_list in pocs.items():
                    self.print_output(f"{cve}:")
                    for poc in poc_list:
                        self.print_output(f"{poc}")

    def get_cves(self, cpe):
        if self.should_print_cves:
            cves = get_cves(cpe)
            self.cves.update(cves)
            return cves
        return []

    def print_single_version_result(self, name, results, version, cpe_base):
        cves = get_cves(cpe_base+version)
        self.cves.update(cves)
        self.print_output(f"{name} {version}{' (' + ', '.join(cves) + ')' if cves else ''}:")
        for v in results:
            self.print_output(" " * self.space + str(v))