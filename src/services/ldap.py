import subprocess
from src.utilities.utilities import get_hosts_from_file


def anon_nv(hosts: list[str], errors, verbose):
    vuln = []
    
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            command = ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "(objectClass=*)"]
            result = subprocess.run(command, text=True, capture_output=True)
            if "ldaperr" not in result.stdout.lower():
                vuln.append(host)
        except Exception as e:print(e)
    
    if len(vuln) > 0:
        print("LDAP anonymous access were found:")
        for v in vuln:
            print(f"    {v}")
        

def anon_console(args):
    anon_nv(get_hosts_from_file(args.file), args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("ldap")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_tls = subparsers.add_parser("anonymous", help="Checks anonymous access")
    parser_tls.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_tls.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_tls.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_tls.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_tls.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_tls.set_defaults(func=anon_console)

