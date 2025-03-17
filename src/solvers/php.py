from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
import re

code = 21

r = r"PHP\/(\d+\.\d+\.\d+)"

def get_default_config():
    return """
["21"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="PHP")
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
    
    for host in hosts:
        try:
            powered_by = get_header_from_url(host, "X-Powered-By")
            m = re.search(r, powered_by)
            if m:
                ver = m.group(0)
                if ver not in versions:
                    versions[ver] = set()
                versions[ver].add(host)      
            else:
                server = get_header_from_url(host, "Server")
                m = re.search(r, server)
                if m:
                    ver = m.group(0)
                    if ver not in versions:
                        versions[ver] = set()
                    versions[ver].add(host)      
                      
        except Exception as e: print(e)

    
    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Detected PHP versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")