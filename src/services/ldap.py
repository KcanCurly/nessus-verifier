import subprocess
from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments


def anon_nv(hosts: list[str], errors, verbose):
    vuln = []
    
    for host in hosts:
        try:
            command = ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "(objectClass=*)"]
            result = subprocess.run(command, text=True, capture_output=True)
            if "ldaperr" not in result.stdout.lower():
                vuln.append(host)
        except Exception as e:
            if errors: print(e)
    
    if len(vuln) > 0:
        print("LDAP anonymous access were found:")
        for v in vuln:
            print(f"    {v}")
        

def anon_console(args):
    anon_nv(get_hosts_from_file(args.target), args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("ldap")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_tls = subparsers.add_parser("anonymous", help="Checks anonymous access")
    add_default_parser_arguments(parser_tls)
    parser_tls.set_defaults(func=anon_console)

