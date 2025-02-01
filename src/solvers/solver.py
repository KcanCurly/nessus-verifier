import argparse
import json
import logging
from src.solvers import tls, kibana, elastic, mongo, oracle, smb, ssh
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

solver_dict ={
    "1": (tls.entry_solver)
}

def all_solver(args):
    with open(args.file, "r") as f:
        for line in f:
            json_output.append(GroupNessusScanOutput.from_json(json.loads(line)))
    

json_output: list[GroupNessusScanOutput] = []

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nessus identified vulnerabilities solver.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv, -vvv, -vvvv, -vvvvvv)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    # 0 - All
    parser_task1 = subparsers.add_parser("all", help="Runs all solvers from json file")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="json file name")
    
    parser_task1.set_defaults(func=all_solver)

    # 1 - TLS Misconfigurations
    parser_task1 = subparsers.add_parser("1", help="TLS Misconfigurations (Version and Ciphers)")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="json file name")
    parser_task1.add_argument("--allow-white-ciphers", action="store_true", required=False, help="White named ciphers are fine from sslscan output")
    parser_task1.set_defaults(func=tls.solve)

    # 3 - SSH Service Misconfigurations
    parser_task1 = subparsers.add_parser("3", help="SSH Service Misconfigurations")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=ssh.entry_solver)
    
    # 5 - SMB Service Misconfigurations
    parser_task1 = subparsers.add_parser("5", help="SMB Service Misconfigurations")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=smb.entry_solver)
        
    # 24 - Kibana
    parser_task1 = subparsers.add_parser("24", help="Kibana")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=kibana.entry_solver)
    
    # 25 - Elastic
    parser_task1 = subparsers.add_parser("25", help="Elastic")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=elastic.entry_solver)
    
    # 26 - MongoDB
    parser_task1 = subparsers.add_parser("26", help="MongoDB")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=mongo.entry_solver)
    
    # 27 - Oracle Database 
    parser_task1 = subparsers.add_parser("27", help="Oracle Database")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=oracle.entry_solver)
    
    
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()