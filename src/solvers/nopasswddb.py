from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
from src.services import mongodb, postgresql
import requests

code = 9

def get_default_config():
    return """
["9"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Database usage without passwrod")
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
            if is_all: return
            if not args.ignore_fail: print("No id found in json file")
            return
        hosts = scan.hosts
    elif args.list_file:
        with open(args.list_file, 'r') as f:
            hosts = [line.strip() for line in f]
            
    if scan:
        hosts = scan.sub_hosts.get("MongoDB Service Without Authentication Detection", [])
        
    mongodb.unauth_nv(hosts)
    
    if scan:
        hosts = scan.sub_hosts.get("PostgreSQL Default Unpassworded Account", [])
        
    postgresql.unpassworded_nv(hosts)
    
    if scan:
        hosts = scan.sub_hosts.get("Elasticsearch Unrestricted Access Information Disclosure", [])
        
    elastic_vuln = []
    for host in hosts:

        try:
            resp = requests.get(f"https://{host}/*", allow_redirects=True, verify=False)
            if resp.status_code in [200]:
                elastic_vuln.append(host)
        except Exception:
            try:
                resp = requests.get(f"http://{host}/*", allow_redirects=True, verify=False)
                if resp.status_code in [200]:
                    elastic_vuln.append(host)
            except: continue
    
    if len(elastic_vuln) > 0:
        print("Elastic Unrestricted Access:")
        for v in elastic_vuln:
            print(f"    {v}")
            