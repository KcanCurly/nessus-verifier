from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import requests

code = 19

def get_default_config():
    return """
["19"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="iDRAC")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    hosts = []
    if args.file:
        scan: GroupNessusScanOutput = find_scan(args.file, code)
        if not scan: 
            if not args.ignore_fail: print("No id found in json file")
            return
        hosts = scan.hosts
    elif args.list_file:
        with open(args.list_file, 'r') as f:
            hosts = [line.strip() for line in f]
    
    for host in hosts:
        try:
            try:
                resp = requests.get(f"https://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False)
            except Exception:
                try:
                    resp = requests.get(f"http://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False)
                except: continue
            
            version = resp.json()["Attributes"]["FwVer"]
            if version:
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
            
        except Exception as e: print(e)


    
    if len(versions) > 0:
        print("Detected iDRAC versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")