from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import requests

def helper_parse(subparser):
    parser_task1 = subparser.add_parser("19", help="iDRAC")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 

def solve(args):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 19)
    if not scan: 
        print("No id found in json file")
        return
    
    for host in scan.hosts:
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