import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments

def brute_nv(hosts, threads, timeout, errors, verbose):
    nmap_file = "/usr/share/nmap/nselib/data/tftplist.txt"
    result = ", ".join(hosts)
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set THREADS {threads}; set ConnectTimeout {timeout}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)

        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
            
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set DICTIONARY {nmap_file}; set THREADS {threads}; set ConnectTimeout {timeout}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)
        
        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
        
            
    except Exception as e:
        if errors: print(e)
    
    if len(vuln) > 0:
        print("TFTP files were found:")
        for k,v in vuln.items():
            print(f"{k}:")
            for a in v:
                print(f"    {a}")
        

def brute_console(args):
    brute_nv(get_hosts_from_file(args.target, False), args.threads, args.timeout, args.errors, args.verbose)
    

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("tftp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_brute = subparsers.add_parser("brute", help="Run TFTP bruteforce on targets")
    add_default_parser_arguments(parser_brute)
    parser_brute.set_defaults(func=brute_console)