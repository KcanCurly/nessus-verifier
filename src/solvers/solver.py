import argparse
from src.solvers import tls

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nessus identified vulnerabilities solver.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1
    parser_task1 = subparsers.add_parser("1", help="TLS Misconfigurations (Version and Ciphers)")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.add_argument("--age", type=int, required=True, help="Age for task1")
    parser_task1.set_defaults(func=tls.entry_solver)
    
    args = parser.parse_args()