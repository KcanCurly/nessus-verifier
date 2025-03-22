from src.utilities.utilities import Version_Vuln_Data, find_scan, add_default_parser_arguments, get_url_response, get_default_context_execution, add_default_solver_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput

code = 25

def get_default_config():
    return """
["25"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Elasticsearch")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1)
    parser_task1.set_defaults(func=solve) 

def solve_version_single(host, timeout, errors, verbose):
    try:
        resp = get_url_response(host, timeout=timeout)
        version = resp.json()['version']['number']
        return Version_Vuln_Data(host, version)
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
        
def solve_version(hosts, threads, timeout, errors, verbose):
    versions = {}
    results: list[Version_Vuln_Data] = get_default_context_execution("Elastic Version", threads, hosts, (solve_version_single, timeout, errors, verbose))
    
    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)
    
    if len(versions) > 0:       
        versions = dict(sorted(versions.items(), reverse=True))
        print("Elastic versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
    

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
    solve_version(hosts, args.threads, args.timeout, args.errors, args.verbose)
    
    