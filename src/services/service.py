from src.utilities.utilities import get_hosts_from_file, get_classic_overall_progress, get_classic_console
import argparse

class Service:
    def __init__(self, name:str, description:str):
        self.name = name
        self.description = description
        self.main_parser = argparse.ArgumentParser(description=description)
        self.sub_parser = self.main_parser.add_subparsers(dest="command")
        
    def add_service_module(self):
        pass
    
    def helper_parser(self, commandparser):
        parser_task1 = commandparser.add_parser(self.name, help=self.description)
        parser_task1.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information (Default = hosts.txt).")
        parser_task1.add_argument("-e", "--errors", action="store_true", help="Show Errors")
        parser_task1.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    
    
class ServiceModule:
    def __init__(self):
        pass