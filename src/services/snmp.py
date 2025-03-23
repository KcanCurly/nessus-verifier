import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments

def default_nv(hosts, threads, timeout, errors, verbose):
    print("Running metasploit snmp_login module, there will be no progression bar")
    hosts = [entry.split(":")[0] for entry in hosts]
    result = ", ".join(hosts)
    vuln = {} 
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/snmp/snmp_login; set RHOSTS {result}; set ConnectTimeout {timeout}; set THREADS {threads}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        if verbose:
            print("stdout:", result.stdout)
            print("stderr:", result.stderr)
        pattern = r"\[\+\] (.*) - Login Successful: (.*);.*: (.*)"
        matches = re.findall(pattern, result.stdout)
        for m in matches:
            if m[0] not in vuln:
                vuln[m[0]] = []
            vuln[m[0]].append(f"{m[1]} - {m[2]}")
                
    except Exception as e:
        if errors: print(f"Error: {e}")
    
    if len(vuln) > 0:
        print("SNMP community strings were found:")
        for k,v in vuln.items():
            print(k)
            for a in v:
                print(f"    {a}")
        

def default_console(args):
    default_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("snmp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_default = subparsers.add_parser("default", help="Checks if default public/private community string is used")
    add_default_parser_arguments(parser_default)
    parser_default.set_defaults(func=default_console)
    