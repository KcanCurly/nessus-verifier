from src.utilities.utilities import get_latest_version


class BaseServiceClass():
    def __init__(self, name: str) -> None:
        self.name = name
        self.subservices= []
        self.eol_product_name = ""
        self.print_cves = False
        self.print_latest_version = False

    def helper_parse(self, commandparser):
        parser_task1 = commandparser.add_parser(self.name)
        subparsers = parser_task1.add_subparsers(dest="command")
        self.subparser = subparsers
        for subservice in self.subservices:
            subservice.helper_parse(self.subparser)

    def register_subservice(self, subservice):
        subservice._set_parent(self)
        self.subservices.append(subservice)

    def print_latest_version2(self, print_title = True):
        if not self.eol_product_name:
            return
        return get_latest_version(self.eol_product_name)
    
    def get_latest_version(self, print_title = True):
        if self.eol_product_name:
            return get_latest_version(self.eol_product_name)

"""
    def solve(self, args):
        for subservice in self.subservices:
            subservice.solve(args)
"""

class ExampleServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("example")