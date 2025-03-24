from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments, get_cves
from src.modules.nv_parse import GroupNessusScanOutput
import re
import subprocess

code = 13

def get_default_config():
    return """
["13"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="VMWare Product Versions")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve)

def solve(args, is_all = False):
    versions = {}

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
    
    r = r"\[\+\] (.*) - Identified (.*)"
    

    result = ", ".join(h.split(":")[0] for h in hosts)
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS {result}; set ConnectTimeout {args.timeout}; set THREADS {args.threads}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        
        matches = re.findall(r, result.stdout)
        for m in matches:
            if m[1] not in versions:
                versions[m[1]] = []
            versions[m[1]].append(f"{m[0]}")
                
    except Exception as e:
        if args.errors : print(e)

    
    if len(versions) > 0:
        print("Detected Vmware Versions:")
        for key, value in versions.items():
            cves = []
            if "esxi" in key.lower(): 
                r = r"VMware ESXi (\d+\.\d+\.\d+)"
                m = re.search(r, key)
                if m: 
                    cves = get_cves(f"cpe:2.3:o:vmware:esxi:{m.group(1)}")
            print(f"{key} ({", ".join(cves)}):")
            for v in value:
                print(f"    {v}")