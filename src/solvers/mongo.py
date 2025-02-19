from pymongo import MongoClient
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 26

def get_default_config():
    return """
["26"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="MongoDB")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 


def solve(args):
    versions: dict[str, str] = {}
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    for host in scan.hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            client = MongoClient(ip, int(port))
            version = client.server_info()['version']
            if version not in versions:
                versions[version] = set()
            versions[version].add(host)  
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(versions) > 0:       
        print("MongoDB versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
    
    
