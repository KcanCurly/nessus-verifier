import argparse
from src.solvers import tls, kibana, elastic, mongo, oracle

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nessus identified vulnerabilities solver.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1 - TLS Misconfigurations
    parser_task1 = subparsers.add_parser("1", help="TLS Misconfigurations (Version and Ciphers)")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=tls.entry_solver)
    

        
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