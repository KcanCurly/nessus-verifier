import subprocess
import re
from src.utilities.utilities import get_hosts_from_file


def users_nv(hosts: list[str], errors, verbose):
    ips = [line.split(":")[0] for line in hosts]
    result = ", ".join(ips)
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use scanner/finger/finger_users; set RHOSTS {result}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"- (.*) Users found: (.*)"
        matches = re.findall(pattern, result.stdout)

        for m in matches:
            if m[0] not in vuln:
                vuln[m[0]] = []
            vuln[m[0]].append(m[1])
            
    except Exception as e: print(e)
    
    if len(vuln) > 0:
        print("Finger service user enumeration:")
        for k,v in vuln.items():
            print(f"    {k}:79 - {", ".join(v)}")
        
def users_console(args):
    users_nv(get_hosts_from_file(args.file), args.errors, args.verbose)

def helper_parser(commandparser):
    parser_task1 = commandparser.add_parser("finger")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_users = subparsers.add_parser("users", help="Enumerates users")
    parser_users.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser_users.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_users.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser_users.set_defaults(func=users_console)
    