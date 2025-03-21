from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import re

code = 35

def get_default_config():
    return """
["35"]
"""

r = r"Jenkins-Version: \S+"

class Version_Vuln_Data():
    def __init__(self, host: str, version: str):
        self.host = host
        self.version = version

def version_single(host: str, timeout: int, verbose: bool):
    try:
        try:
            resp = requests.get(f"https://{host}", allow_redirects=True, verify=False, timeout=timeout)
        except:
            try:
                resp = requests.get(f"http://{host}", allow_redirects=True, verify=False, timeout=timeout)
            except: return

        m = re.search(r, resp.text)
        if m: return  Version_Vuln_Data(host, m.group(0))

    except:return

def version_nv(hosts: list[str], threads: int, timeout: int, verbose: bool ):
    versions = {}
    futures = []
    results: list[Version_Vuln_Data] = []

    with ThreadPoolExecutor(threads) as executor:
        for host in hosts:
            future = executor.submit(version_single, host, timeout, verbose)
            futures.append(future)
        for a in as_completed(futures):

            results.append(a.result())
                
    for r in results:
        if not r: continue
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)

    if len(versions) > 0:
        print("Detected Jenkins versions:")
        versions = dict(sorted(versions.items(), reverse=True))
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
                

def solve(args, is_all = False):
    l= logger.setup_logging(args.verbose)
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
    
    version_nv(hosts, args.threads, args.timeout, args.verbose)
    
def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Jenkins")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_task1.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_task1.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_task1.set_defaults(func=solve) 