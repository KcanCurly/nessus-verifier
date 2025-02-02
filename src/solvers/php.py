from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

def helper_parse(subparser):
    parser_task1 = subparser.add_parser("21", help="PHP")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 

def solve(args):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 21)
    if not scan: 
        print("No id found in json file")
        return
    
    for host in scan.hosts:
        try:
            version = get_header_from_url(host, "x-powered-by")
            if version:
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
            else: print("Version no get")
            
        except Exception as e: print(e)

    
    if len(versions) > 0:
        print("Detected PHP versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")