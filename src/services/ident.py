import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments

def users_nv(hosts: list[str], ports: list[str], errors, verbose):
    print("Running metasploit Ident service module, there will be no progression bar")
    vuln = {}
    try:
        for ip in hosts:
            command = ["ident-user-enum", ip, *ports]
            result = subprocess.run(command, text=True, capture_output=True)
            pattern = r"(.*):(.*) (.*)"
            matches = re.findall(pattern, result.stdout)

            for m in matches:
                if m[0] not in vuln:
                    vuln[m[0]] = []
                vuln[m[0]].append(f"{m[1]} - {m[2]}")
            
    except Exception as e:
        if errors: print("Error:", e)
    
    if len(vuln) > 0:
        print("Ident service user enumeration:")
        for k,v in vuln.items():
            print(f"    {k}:113 - {", ".join(v)}")
        

def users_console(args):
    users_nv(get_hosts_from_file(args.target, False), args.ports, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ident")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_enum = subparsers.add_parser("users", help="Enumerates users")
    parser_enum.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_enum.add_argument("-p", "--ports", nargs="+", default=["22", "80", "113", "443"], help="Ports to enumerate")
    add_default_parser_arguments(parser_enum, False)
    parser_enum.set_defaults(func=users_console)