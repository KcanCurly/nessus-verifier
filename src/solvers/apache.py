from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import re

code = 11

def get_default_config():
    return """
["11"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Apache Version")
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
    
    r = r"Apache/(.*)"
    
    for host in hosts:
        header = get_header_from_url(host, "Server")
        if header:
            m = re.search(r, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                m = "Apache " + m
                if m not in versions:
                    versions[m] = set()
                versions[m].add(host)

    
    if len(versions) > 0:
        print("Detected Apache Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")