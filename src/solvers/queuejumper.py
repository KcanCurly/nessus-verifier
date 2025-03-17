import subprocess
import re
from src.utilities.utilities import get_hosts_from_file
from src.services import snmp
from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger


code = 28

def get_default_config():
    return """
["28"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Queuejumper")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
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
    snmp.default_nv(hosts, args.verbose)
            

def default_nv(hosts, verbose=False):
    hosts = [entry.split(":")[0] for entry in hosts]
    result = ", ".join(hosts)
    vuln = []
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/msmq/cve_2023_21554_queuejumper; set RHOSTS {result}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        if verbose:
            print("stdout:", result.stdout)
            print("stderr:", result.stderr)
        pattern = r"\[\+\] (.*)\s+ - MSMQ vulnerable to CVE-2023-21554"
        matches = re.findall(pattern, result.stdout)
        for m in matches:
            vuln.append(f"{m[0]}")
                
    except Exception:pass
    
    if len(vuln) > 0:
        print("Vulnerable to CVE-2023-21554 (QueueJumper):")
        for v in vuln:
            print(v)
        

def default_console(args):
    default_nv(get_hosts_from_file(args.file), args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("snmp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_smbv1 = subparsers.add_parser("default", help="Checks if easy to guess public/private community string is used")
    parser_smbv1.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_smbv1.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_smbv1.set_defaults(func=default_console)
    