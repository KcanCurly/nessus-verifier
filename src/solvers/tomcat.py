from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import requests
import re

def solve(args):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 10)
    if not scan: 
        print("No id found in json file")
        return
    
    r = r"<title>Apache Tomcat/(.*)</title>"
    
    hosts = scan.hosts
    for host in hosts:
        try:
            try:
                resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
            except requests.exceptions.SSLError:
                try:
                    resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
                except: continue
            
            m = re.search(r, resp.text)
            if m:
                version = m.group(0)
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
                
            
        except Exception as e: print(f"Error for {host}:", e)

    
    if len(versions) > 0:
        print("Detected Apache Tomcat Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")