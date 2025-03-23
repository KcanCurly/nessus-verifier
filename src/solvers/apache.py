from src.utilities.utilities import Version_Vuln_Data, find_scan, get_header_from_url, add_default_parser_arguments, get_default_context_execution, add_default_solver_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput
import re
import requests

code = 11

def get_default_config():
    return """
["11"]
"""

cpe = "cpe:2.3:a:apache:tomcat:<version>:*:*:*:*:*:*:*"

def get_cves(version):
    cpe = f"cpe:2.3:a:apache:tomcat:{version}"
    params = {
        "cpe23": cpe,
        "count": "false",
        "is_key": "false",
        "sort_by_epss": "true",
        "skip": "0",
        "limit": "10",
    }
    resp = requests.get(f'https://cvedb.shodan.io/cves', data=params)
    resp_json = resp.json()
    cves = resp_json["cves"]
    cve_ids = []
    for c in cves:
        cve_ids.append(c["cve_id"])
    return cve_ids

    
    

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Apache")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 

version_regex = r"Apache/(.*)"

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
    

                
def solve_version(hosts, threads, timeout, errors, verbose):
    versions = {}
    results: list[Version_Vuln_Data] = get_default_context_execution("Apache Version", threads, hosts, (solve_version_single, timeout, errors, verbose))
    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)

    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Detected Apache Versions:")
        for key, value in versions.items():
            cves = get_cves(key)
            print(f"{key} ({", ".join(cves)}):")
            for v in value:
                print(f"    {v}")
                
def solve_version_single(host, timeout, errors, verbose):
    try:
        header = get_header_from_url(host, "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                m = "Apache " + m
                return Version_Vuln_Data(host, m)

    except Exception as e:
        if errors: print(f"Error for {host}: {e}")