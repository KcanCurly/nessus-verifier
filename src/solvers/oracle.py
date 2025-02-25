import re
import subprocess
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 27

def get_default_config():
    return """
["27"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Oracle Database")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
    versions: dict[str, str] = {}
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
    
    version_regex = r"Version (\d+\.\d+\.\d+\.\d+\.\d+)"

    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        try:
            command = ["tnscmd10g", "version", "-h", ip, "-p", port]
            c = subprocess.run(command, text=True, capture_output=True)
            
            m = re.search(version_regex, c.stdout)
            if m:
                version = m.group(1)
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
                
            
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(versions) > 0:       
        print("Oracle TNS versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
    