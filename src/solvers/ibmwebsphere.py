import re
from src.utilities.utilities import Version_Vuln_Data, find_scan, add_default_solver_parser_arguments, add_default_parser_arguments, get_url_response, get_default_context_execution
from src.modules.nv_parse import GroupNessusScanOutput

code = 29

def get_default_config():
    return """
["29"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="IBM WebSphere Version")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 

r = r"<title>WebSphere Application Server V(.*)</title>"
liberty = r"<title>WebSphere Liberty (.*)</title>"
    
def solve_version_single(host, timeout, errors, verbose):
    try:
        resp = get_url_response(host)
        m = re.search(r, resp.text)
        if m:
            version = m.group(1)
            version = f"WebSphere Application Server {version}"
            return Version_Vuln_Data(host, version)

        else:
            m = re.search(liberty, resp.text)
            if m:
                version = m.group(1)
                version = f"WebSphere Liberty {version}"
                return Version_Vuln_Data(host, version)
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
    
def solve_version(hosts: list[str], threads: int, timeout: int, errors: bool, verbose: bool):
    versions = {}
    results: list[Version_Vuln_Data] = get_default_context_execution("IBM WebSphere Version", threads, hosts, (solve_version_single, timeout, errors, verbose))
    
    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)
        
    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Detected IBM WebSphere Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")

def solve(args):
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