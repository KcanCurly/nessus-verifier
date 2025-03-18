import subprocess
import os

def version_nv(file, port = "5030-5080", sippts_output = "nv-asterisk-data"):
    vuln = {}
    command = ["sippts", "scan", "-f", file, "-r", port, "-p", "all", "-o", sippts_output]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        
        with open("nv-asterisk-data") as f:
            print(f.read())
        os.remove("nv-asterisk-data")

    except Exception as e: print(e)

def version_console(args):
    version_nv(args.file, args.port, args.sippts_output)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("asterisk")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks Asterisk version")
    parser_version.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_version.add_argument("-p", "--port", type=str, default="5030-5080", help="sippts port argument (Default = 5030-5080)")
    parser_version.add_argument("-o", "--sippts-output", type=str, default="nv-asterisk-data", help="sippts output option (Default = nv-asterisk-data)")
    parser_version.set_defaults(func=version_console)