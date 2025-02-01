import re
import argparse
import requests
import urllib3
import subprocess
from src.utilities.utilities import get_hosts_from_file

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

def entry_solver(args):
    solve(args.file)

def entry_cmd():
    parser = argparse.ArgumentParser(description="Oracle Database")
    parser.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    
    args = parser.parse_args()
    
    entry_solver(args)

def solve(hosts, white_results_are_good = False):
    versions: dict[str, str] = {}
    
    
    version_regex = r"Version (\d+\.\d+\.\d+\.\d+\.\d+)"
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        try:
            command = ["tnscmd10g", "version", "-h", ip, "-p", port]
            c = subprocess.run(command, text=True, capture_output=True)
            
            m = re.search(version_regex, c.stdout)
            if m:
                version = m.group(1)
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)
                
            
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(versions) > 0:       
        print("Oracle TNS versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
    
    
            
if __name__ == "__main__":
    entry_cmd()