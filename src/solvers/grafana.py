from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import requests
import re

code = 22

def get_default_config():
    return """
["22"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Apache Tomcat Version")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan: 
        print("No id found in json file")
        return
    
    r = r'Grafana v(.*) \('
    
    hosts = scan.hosts
    for host in hosts:
        try:
            try:
                resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
            except Exception:
                try:
                    resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
                except: continue
            
            m = re.search(r, resp.text)
            if m:
                version = m.group(1)
                version = "Grafana " + version
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
        except Exception as e: l.v3(f"Grafana Version check failed for {host}: {e}")

    
    if len(versions) > 0:
        print("Detected Grafana Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")