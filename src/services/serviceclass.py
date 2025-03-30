import src.services.servicesubclass

class BaseServiceClass():
    def __init__(self, name: str) -> None:
        self.name = name
        self.subservices: list[src.services.servicesubclass.BaseSubServiceClass] = []

    def helper_parse(self, commandparser):
        parser_task1 = commandparser.add_parser(self.name)
        subparsers = parser_task1.add_subparsers(dest="command")
        self.subparser = subparsers

    def register_subservice(self, subservice: src.services.servicesubclass.BaseSubServiceClass):
        subservice._set_parent(self)
        subservice.helper_parse(self.subparser)
        self.subservices.append(subservice)
