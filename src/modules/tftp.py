import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
from src.utilities import get_hosts_from_file


def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    ips = [line.split(":")[0] for line in hosts]
    result = ", ".join(ips)
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/tftp/tftpbrute; set RHOSTS {result}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"\[\+\] Found (.*) on (.*)\s+"
        matches = re.findall(pattern, result.stdout)

        for m in matches:
            if m[1] not in vuln:
                vuln[m[1]] = []
                vuln[m[1]].append(m[0])
            
    except Exception as e: print(e)
    
    if len(vuln) > 0:
        print("TFTP files were found:")
        for k,v in vuln.items():
            print(k, ":69")
            for a in v:
                print(f"\t{a}")
        

def main():
    parser = argparse.ArgumentParser(description="DNS module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("--domain", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args, args.filename or "hosts.txt")