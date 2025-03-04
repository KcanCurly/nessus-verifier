import argparse

import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, get_classic_console

def enum_nv(l: list[str], output: str = None, verbose: bool = False):
    versions = {}
    info_vuln: dict[str: list[str]] = {}

    result = ", ".join(l)

    try:
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/gather/zookeeper_info_disclosure; set RHOSTS {result}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        host_start = r"\[\*\] (.*)\s+ - Using a timeout of"
        zookeeper_version = r"zookeeper.version=(.*),"
        env = r"Environment:"
        
        
        host = ""
        
        for line in result.stdout.splitlines():
            try:
                matches = re.search(host_start, line)
                if matches:
                    host = matches.group(1)
                    continue
                
                matches = re.search(zookeeper_version, line)
                if matches:
                    ver = matches.group(1).split("-")[0]
                    if ver not in versions:
                        versions[ver] = set()
                    versions[ver].add(host)
                    continue
                    
                matches = re.search(env, line)
                if matches:
                    info_vuln[host] = []
                    continue
                if "user.name" in line or "user.home" in line or "user.dir" in line or "os.name" in line or "os.arch" in line or "os.version" in line or "host.name" in line:
                    info_vuln[host].append(line)
                    
            except: pass
        
            
    except:pass

    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Apache Zookeeper Versions:")
        for k,v in versions.items():
            print(f"{k}:")
            for a in v:
                print(f"    {a}")
                
    if len(info_vuln) > 0:
        print("Apache Zookeeper Information Disclosure Detected:")
        for k,v in info_vuln.items():
            print(f"{k}:2181:")
            for a in v:
                print(f"    {a}")
        


        

def enum_console(args):
    enum_nv(get_hosts_from_file(args.file, False), args.verbose)
    

def main():
    parser = argparse.ArgumentParser(description="Zookeeper module of nessus-verifier.")
    subparsers = parser.add_subparsers(dest="command")
    
    brute_parser = subparsers.add_parser("enum", help="Run enumeration on zookeeper host") # Don't want to have threads because we parse line by line, multiple threads can break the parsing logic
    brute_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    brute_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    brute_parser.set_defaults(func=enum_console)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()