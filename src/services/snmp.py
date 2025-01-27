import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
from src.utilities import get_hosts_from_file


def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts, False)
    result = ", ".join(hosts)
    vuln = {}
    command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/scanner/snmp/snmp_login; set RHOSTS {result}; run; exit"]
    try:
        result = subprocess.run(command, text=True, capture_output=True)
        if len(result.stdout) > 0: print(result.stdout)
        if len(result.stderr) > 0: print(result.stderr)
        pattern = r"\[\+\] (.*) - Login Successful: (.*) (.*);"
        matches = re.findall(pattern, result.stdout)
        for m in matches:
            if m[0] not in vuln:
                vuln[m[0]] = []
            vuln[m[0]].append(f"{m[1]} - {m[2]}")
                
    except Exception:pass
    
    if len(vuln) > 0:
        print("SNMP community strings were found:")
        for k,v in vuln.items():
            print(k)
            for a in v:
                print(f"\t{a}")
        

def main():
    parser = argparse.ArgumentParser(description="SNMP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args, args.filename or "hosts.txt")