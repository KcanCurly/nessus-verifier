import subprocess
import os
from src.utilities.utilities import Version_Vuln_Data, get_hosts_from_file, add_default_parser_arguments, get_default_context_execution

def version_nv(file, port, sippts_output, threads, timeout, errors, verbose):
    vuln = {}
    command = ["sippts", "scan", "-f", file, "-r", port, "-p", "all", "-o", sippts_output]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        
        with open(sippts_output) as f:
            print(f.read())
        os.remove(sippts_output)

    except Exception as e: 
        if errors: print("Error:", e)

def version_console(args):
    version_nv(get_hosts_from_file(args.target), args.port, args.sippts_output, args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("asterisk")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks Asterisk version")
    parser_version.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_version.add_argument("-p", "--port", type=str, default="5030-5080", help="sippts port argument (Default = 5030-5080)")
    parser_version.add_argument("-o", "--sippts-output", type=str, default="nv-asterisk-data", help="sippts output option (Default = nv-asterisk-data)")
    add_default_parser_arguments(parser_version, False)
    parser_version.set_defaults(func=version_console)