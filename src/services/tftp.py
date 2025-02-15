import argparse
import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, get_classic_console
import nmap


def brute_nv(l: list[str], output: str = None, threads: int = 10, verbose: bool = False):
    nmap_file = "/usr/share/nmap/nselib/data/tftplist.txt"
    console = get_classic_console()
    
    nm = nmap.PortScanner()
    if verbose: console.print(f"Starting TFTP Brute, i can't show you progress")
    host2 = []
    for host in l:
            try:
                ip = host.split(":")[0]
                port = host.split(":")[1]
                nm.scan(ip, port, arguments=f'-sV -sU')
                
                if ip in nm.all_hosts():
                    nmap_host = nm[ip]
                    if 'tftp' in nmap_host['udp'][int(port)]['name'].lower():
                        host2.append(host)
                        
            except: pass
    
    if not host2: 
        if verbose: console.print("None of the ports were accessible")
        return
    
    result = ", ".join(host2)
    
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set THREADS {str(threads)}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)

        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = []
            vuln[m[1]].append(m[0])
            
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; set DICTIONARY {nmap_file}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)
        
        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = set()
            vuln[m[1]].add(m[0])
        
            
    except Exception as e: print(e)
    
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
        

def brute_console(args):
    brute_nv(get_hosts_from_file(args.file, False), args.output, args.threads, args.verbose)
    

def main():
    parser = argparse.ArgumentParser(description="TFTP module of nessus-verifier.")
    subparsers = parser.add_subparsers(dest="command")
    
    brute_parser = subparsers.add_parser("brute", help="Run TFTP bruteforce on targets")
    brute_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    brute_parser.add_argument("-o", "--output", type=str, required=False, help="Output file, append if file exists.")
    brute_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    brute_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    brute_parser.set_defaults(func=brute_console)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()