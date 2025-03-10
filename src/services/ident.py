import subprocess
import re
from src.utilities.utilities import get_hosts_from_file

def users_nv(hosts: list[str], ports: list[str], errors, verbose):
    hosts = get_hosts_from_file(hosts)
    ips = [line.split(":")[0] for line in hosts]
    result = ", ".join(ips)
    vuln = {}
    try:
        for ip in ips:
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
    users_nv(args.file, args.ports, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ident")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_anon = subparsers.add_parser("users", help="Enumerates users")
    parser_anon.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_anon.add_argument("-p", "--ports", nargs="+", default=["22", "80", "113", "443"], help="Ports to enumerate")
    parser_anon.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_anon.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_anon.set_defaults(func=users_console)