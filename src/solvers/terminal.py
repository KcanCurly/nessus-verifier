import subprocess
import re
from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput
import os

code = 8

def get_default_config():
    return """
["8"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Terminal Services Misconfigurations")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve)
    
issue_re = r"\[-\] (.*) has issue (.*)"

def solve(args, is_all = False):

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
    
    
    print("Running rdp-sec-check.pl, there will be no progression bar")
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
