import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
from src.utilities.utilities import get_hosts_from_file

def default_nv(hosts, verbose=False):
    result = ", ".join(hosts)
    vuln = {} 
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/snmp/snmp_login; set RHOSTS {result}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        if verbose:
            print("stdout:", result.stdout)
            print("stderr:", result.stderr)
        pattern = r"\[\+\] (.*) - Login Successful: (.*);"
        matches = re.findall(pattern, result.stdout)
        for m in matches:
            if m[0] not in vuln:
                vuln[m[0]] = []
            vuln[m[0]].append(f"{m[1]}")
                
    except Exception:pass
    
    if len(vuln) > 0:
        print("SNMP community strings were found:")
        for k,v in vuln.items():
            print(k)
            for a in v:
                print(f"    {a}")
        

def default_console(args):
    default_nv(get_hosts_from_file(args.file, False), args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("snmp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_smbv1 = subparsers.add_parser("default", help="Checks if easy to guess public/private community string is used")
    parser_smbv1.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_smbv1.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_smbv1.set_defaults(func=default_console)
    