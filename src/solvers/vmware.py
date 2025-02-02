from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import re
import subprocess

def helper_parse(subparser):
    parser_task1 = subparser.add_parser("13", help="VMWare Product Versions")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)

def solve(args):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 13)
    if not scan: 
        print("No id found in json file")
        return
    
    r = r"\[\+\] (.*) - Identified (.*)"
    
    hosts = scan.hosts
    result = ", ".join(h.split(":")[0] for h in hosts)
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/vmware/esx_fingerprint; set RHOSTS {result}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        
        matches = re.findall(r, result.stdout)
        for m in matches:
            if m[0] not in versions:
                versions[m[1]] = []
            versions[m[1]].append(f"{m[0]}")
                
    except Exception:pass

    
    if len(versions) > 0:
        print("Detected Vmware Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")