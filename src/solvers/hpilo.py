from src.utilities.utilities import Version_Vuln_Data, get_cves, find_scan, get_url_response, get_default_context_execution, add_default_parser_arguments, add_default_solver_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput
from packaging.version import parse

code = 34

def get_default_config():
    return """
["34"]
"""

def solve_version_single(host, timeout, errors, verbose):
    try:
        resp = get_url_response(f"{host}/json/login_session")        
        big_version = resp.json()["moniker"]["PRODGEN"]
        version = resp.json()["version"]
        return Version_Vuln_Data(host, f"{big_version} - {version}")
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")

def solve_version(hosts: list[str], threads: int, timeout: int, errors, verbose: bool):
    versions = {}
    results: list[Version_Vuln_Data] = get_default_context_execution("HP iLO Version", threads, hosts, (solve_version_single, timeout, errors, verbose))

    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)
    
    if len(versions) > 0:
        print("Detected HP iLO versions:")
        versions = dict(sorted(versions.items(), reverse=True))
        for key, value in versions.items():
            """
            cves = get_cves(f"cpe:2.3:a:grafana:grafana:{key}")
            if cves: print(f"HP iLO {key} ({", ".join(cves)}):")
            else: print(f"HP iLO {key}:")
            """
            print(f"HP iLO {key}:")
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
    
def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="HP iLO")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 