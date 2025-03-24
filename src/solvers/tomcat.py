from src.utilities.utilities import Version_Vuln_Data, find_scan, add_default_solver_parser_arguments, add_default_parser_arguments, get_url_response, get_default_context_execution, get_cves
from src.modules.nv_parse import GroupNessusScanOutput
import re
from packaging.version import parse

code = 10

def get_default_config():
    return """
["10"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Apache Tomcat Version")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 

r = r"<title>Apache Tomcat\/(.*)<\/title>"
r1 = r"Apache Tomcat\/(\d+\.\d+\.\d+)"

def solve_version_single(host, timeout, errors, verbose):
    try:
        resp = get_url_response(host, timeout=timeout)

        m = re.search(r1, resp.text, re.MULTILINE)
        if m: return Version_Vuln_Data(host, m.group(1))           
        
    except Exception as e: 
        if errors: print(f"Error for {host}: {e}")

def solve_version(hosts, threads, timeout, errors, verbose):
    versions = {}
    results: list[Version_Vuln_Data] = get_default_context_execution("Apache Tomcat Version", threads, hosts, (solve_version_single, timeout, errors, verbose))
    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)

    if len(versions) > 0:
        versions = dict(
            sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
        )

        print("Detected Apache Tomcat Versions:")
        for key, value in versions.items():
            if key.startswith("8"): print(f"Apache Tomcat/{key} (EOL):")
            else:
                cves = get_cves(f"cpe:2.3:a:apache:tomcat:{key}")
                if cves: print(f"Apache/{key} ({", ".join(cves)}):")
                else: print(f"Apache/{key}:")
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