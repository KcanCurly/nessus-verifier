import argparse
import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, get_classic_console
import nmap
import traceback

def enum_nv(l: list[str], output: str = None, threads: int = 10, verbose: bool = False):

    result = ", ".join(l)
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/gather/zookeeper_info_disclosure; set RHOSTS {result}; set THREADS {str(threads)}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        host_start = r"\[\*\] (.*)\s+ - Using a timeout of"
        
        host = ""
        
        for line in result.stdout.splitlines():
            matches = re.search(host_start, line)
            if matches:
                host = matches.group(1)
                print(host)
            
            pass
        
        """
        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
        """
            

        
            
    except:pass
    """
    if len(vuln) > 0:
        print("TFTP files were found:")
        for k,v in vuln.items():
            print(f"{k}:69:")
            for a in v:
                print(f"    {a}")
        
        if output:
            with open(output, "a") as file:
                print("TFTP files were found:", file=file)
                for k,v in vuln.items():
                    print(f"{k}:69:", file=file)
                    for a in v:
                        print(f"    {a}", file=file)
    """
        

def enum_console(args):
    enum_nv(get_hosts_from_file(args.file, False), args.output, args.threads, args.verbose)
    

def main():
    parser = argparse.ArgumentParser(description="Zookeeper module of nessus-verifier.")
    subparsers = parser.add_subparsers(dest="command")
    
    brute_parser = subparsers.add_parser("enum", help="Run enumeration on zookeeper host")
    brute_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    brute_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    brute_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    brute_parser.set_defaults(func=enum_console)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()