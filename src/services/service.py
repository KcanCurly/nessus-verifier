from src.utilities.utilities import get_hosts_from_file, get_classic_progress, get_classic_console
import argparse

class Service:
    def __init__(self, name:str, description:str):
        self.name = name
        self.description = description
        self.main_parser = argparse.ArgumentParser(description=description)
        self.sub_parser = self.main_parser.add_subparsers(dest="command")
        
    def add_service_module(self):
        pass

    
class Vuln_Data:
    def __init__(self):
        pass
    
class ServiceModule:
    def __init__(self):
        pass