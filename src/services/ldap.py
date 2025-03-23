import subprocess
from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments

def anon_single(host, timeout, errors, verbose):
    try:
        command = ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "(objectClass=*)"]
        result = subprocess.run(command, text=True, capture_output=True)
        if "ldaperr" not in result.stdout.lower():
            return host
    except Exception as e: 
        if errors: print(f"Error for {host}: {e}")

def anon_nv(hosts, threads, timeout, errors, verbose):
    results: list[str] = get_default_context_execution("LDAP Anonymous", threads, hosts, (anon_single, timeout, errors, verbose))

    if len(results) > 0:
        print("LDAP anonymous access were found:")
        for v in results:
            print(f"    {v}")
        

def anon_console(args):
    anon_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("ldap")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_anon = subparsers.add_parser("anonymous", help="Checks anonymous access")
    add_default_parser_arguments(parser_anon)
    parser_anon.set_defaults(func=anon_console)

