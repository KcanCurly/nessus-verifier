import subprocess
import re
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 8

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Terminal Services Misconfigurations")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)
    

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan and not args.ignore_fail: 
        print("No id found in json file")
        return
    
    vuln = {}
    
    issue_re = r"[-] (.*) has issue (.*)"
    
    # We need to create a file for rdp-sec-check.pl
    with open("temp_hosts.txt", "w") as f:
        for host in scan.hosts:
            f.write(host)
            
    for host in scan.hosts:
        try:
            command = ["perl", "~/rdp-sec-check/rdp-sec-check.pl", host]
            result = subprocess.run(command, text=True, capture_output=True)
            
            matches = re.findall(issue_re, result.stdout)
            
            for match in matches:
                if match[0] not in vuln:
                    vuln[match[0]] = []
                vuln[match[0]].append(match[1])
        except: pass
            
    if len(vuln) > 0:
        print("Terminal Misconfigurations Detected:")
        for key, value in vuln.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
