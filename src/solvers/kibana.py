import re
import requests
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

def helper_parse(subparser):
    parser_task1 = subparser.add_parser("24", help="Kibana")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 

def solve(args):
    versions: dict[str, str] = {}

    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 24)
    
    version_regex = r'data="{&quot;version&quot;:&quot;(.*)&quot;,&quot;buildNumber'

    for host in scan.hosts:
        try:
            try:
                resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
            except Exception:
                try:
                    resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
                except: continue
            
            m = re.search(version_regex, resp.text)
            if m:
                version = m.group(1)
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
                
            
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(versions) > 0:       
        print("Kibana versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
    
    
