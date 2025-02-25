import subprocess
import re
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import os

code = 8

def get_default_config():
    return """
["8"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Terminal Services Misconfigurations")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve)
    

def solve(args, is_all = False):
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
    
    vuln = {}
    
    issue_re = r"\[-\] (.*) has issue (.*)"
            
    for host in hosts:
        try:
            p = os.path.join(os.path.expanduser("~"), "rdp-sec-check", "rdp-sec-check.pl")
            command = ["perl", p, host]
            result = subprocess.run(command, text=True, capture_output=True)
            
            matches = re.findall(issue_re, result.stdout)
            
            for match in matches:
                if match[0] not in vuln:
                    vuln[match[0]] = []
                vuln[match[0]].append(match[1])
        except Exception as e: print(e)
            
    if len(vuln) > 0:
        print("Terminal Misconfigurations Detected:")
        for key, value in vuln.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
