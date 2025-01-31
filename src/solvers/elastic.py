import subprocess
import re
import ssl
import socket
import argparse
import requests
import urllib3
from src.utilities import get_hosts_from_file

urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

def entry_solver(args):
    solve(args.file)

def entry_cmd():
    parser = argparse.ArgumentParser(description="Kibana")
    parser.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    
    args = parser.parse_args()
    
    entry_solver(args)

def solve(hosts, white_results_are_good = False):
    versions: dict[str, str] = {}
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            try:
                resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
            except ssl.SSLError:
                try:
                    resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
                except: continue
            
            version = resp.json()['version']['number']
            if version not in versions:
                versions[version] = set()
            versions[version].add(host)
                
            
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(versions) > 0:       
        print("Elastic versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
    
    
            
if __name__ == "__main__":
    entry_cmd()