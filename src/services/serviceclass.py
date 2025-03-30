class BaseServiceClass():
    def __init__(self, name: str) -> None:
        self.name = name
        self.subservices= []

    def helper_parse(self, commandparser):
        parser_task1 = commandparser.add_parser(self.name)
        subparsers = parser_task1.add_subparsers(dest="command")
        self.subparser = subparsers
        for subservice in self.subservices:
            subservice.helper_parse(self.subparser)

    def register_subservice(self, subservice):
        subservice._set_parent(self)
        self.subservices.append(subservice)
