from src.utilities.utilities import Version_Vuln_Data, find_scan, get_url_response, get_default_context_execution, add_default_parser_arguments, add_default_solver_parser_arguments, get_cves
from src.modules.nv_parse import GroupNessusScanOutput
import re
from packaging.version import parse

code = 22

def get_default_config():
    return """
["22"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Grafana")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 
        
version_regex = r'Grafana v(.*) \('
        
def solve_version_single(host, timeout, errors, verbose):
    try:
        resp = get_url_response(host, timeout=timeout)
        m = re.search(version_regex, resp.text)
        if m:
            version = m.group(1)
        return Version_Vuln_Data(host, version)
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")

def solve_version(hosts, threads, timeout, errors, verbose):
    results: list[Version_Vuln_Data] = get_default_context_execution("Grafana Version", threads, hosts, (solve_version_single, timeout, errors, verbose))
    versions = {}
    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)
    
    if len(versions) > 0:
        versions = dict(
            sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
        )
        print("Detected Grafana Versions:")
        for key, value in versions.items():
            cves = get_cves(f"cpe:2.3:a:grafana:grafana:{key}")
            if cves: print(f"Grafana {key} ({", ".join(cves)}):")
            else: print(f"Grafana {key}:")
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
    
