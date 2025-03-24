from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments, get_default_context_execution, get_url_response
from src.modules.nv_parse import GroupNessusScanOutput
from src.services import mongodb, postgresql

code = 9

def get_default_config():
    return """
["9"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Database usage without password")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 
    
def solve_elastic_version_single(host, timeout, errors, verbose):
    try:
        resp = get_url_response(host, timeout)
        if resp.status_code in [200]:
            return host
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
        
def solve_elastic_version(hosts, threads, timeout, errors, verbose):
    results: list[str] = get_default_context_execution("Elasticsearch Unrestricted Access Information Disclosure", threads, hosts, (solve_elastic_version_single, timeout, errors, verbose))

    if len(results) > 0:
        print("Elastic Unrestricted Access:")
        for r in results:
            print(f"    {r}")

def solve(args, is_all = False):
    hosts = []
    if args.file:
        scan: GroupNessusScanOutput = find_scan(args.file, code)
        if not scan:
            if is_all: return
            if not args.ignore_fail: print("No id found in json file")
            return
        hosts = scan.hosts
    elif args.list_file:
        with open(args.list_file, 'r') as f:
            hosts = [line.strip() for line in f]
            
    if scan:
        hosts = scan.sub_hosts.get("MongoDB Service Without Authentication Detection", [])
        mongodb.unauth_nv(hosts, args.threads, args.timeout, args.errors, args.verbose)
        hosts = scan.sub_hosts.get("PostgreSQL Default Unpassworded Account", [])
        postgresql.unpassworded_nv(hosts, args.threads, args.timeout, args.errors, args.verbose)
        hosts = scan.sub_hosts.get("Elasticsearch Unrestricted Access Information Disclosure", [])
        solve_elastic_version(hosts, args.threads, args.timeout, args.errors, args.verbose)
