import argparse
import os
import socket
from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments

def usage_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))

        # Receive and print the response
        response = s.recv(4096).decode(errors="ignore")  # Decode safely
        print("[*] Systat Response:\n", response)

        # Close the connection
        s.close()
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
        
def usage_nv(hosts, threads, timeout, errors, verbose):
    results = get_default_context_execution("Systat Usage", threads, hosts, (usage_single, timeout, errors, verbose))
    
    if len(results) > 0:
        print("Systat Usage Detected:")
        for value in results:
            print(f"{value}")
    
        
def usage_console(args):
    usage_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("systat")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_usage = subparsers.add_parser("usage", help="Checks usage")
    add_default_parser_arguments(parser_usage)
    parser_usage.set_defaults(func=usage_console)