from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
import requests
import re

code = 10

def get_default_config():
    return """
["10"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Apache Tomcat Version")
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
    
    r = r"<title>Apache Tomcat\/(.*)<\/title>"
    r1 = r"Apache Tomcat\/(\d+\.\d+\.\d+)"

    for host in hosts:
        try:
            try:
                resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
            except Exception:
                try:
                    resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
                except: continue

            m = re.search(r1, resp.text, re.MULTILINE)
            if m:
                version = m.group(0)
                version = "Apache Tomcat/" + version
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)                
            
        except Exception as e: print(f"Error for {host}:", e)

    
    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Detected Apache Tomcat Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")