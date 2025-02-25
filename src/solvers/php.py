from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 21

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
            version = get_header_from_url(host, "X-Powered-By", args.verbose)
            if version:
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)            
        except Exception as e: print(e)

    
    if len(versions) > 0:
        print("Detected PHP versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")