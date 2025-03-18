import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, get_classic_console
import nmap

def brute_nv(hosts: list[str], threads: int = 10, verbose: bool = False):
    nmap_file = "/usr/share/nmap/nselib/data/tftplist.txt"
    console = get_classic_console()

    result = ", ".join(hosts)
    
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set THREADS {str(threads)}; set ConnectTimeout 10; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)

        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
            
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set DICTIONARY {nmap_file}; set THREADS {str(threads)}; set ConnectTimeout 10; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)
        
        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
        
            
    except Exception as e: pass
    
    if len(vuln) > 0:
        print("TFTP files were found:")
        for k,v in vuln.items():
            print(f"{k}:")
            for a in v:
                print(f"    {a}")
        

        

def brute_console(args):
    brute_nv(get_hosts_from_file(args.file, False), args.threads, args.verbose)
    

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("tftp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    brute_parser = subparsers.add_parser("brute", help="Run TFTP bruteforce on targets")
    brute_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    brute_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    brute_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    brute_parser.set_defaults(func=brute_console)