import argparse
import configparser
import os
from pathlib import Path
import requests
from src.utilities import get_hosts_from_file

exch_versions = {
    "15.2.1544.14" : "Exchange Server 2019 CU14 Nov24SUv2",
}


def version_check(directory_path, config, verbose, hosts = "hosts.txt"):
    d = {}
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            url = f"https://{host}"
            autodiscovery_url = url + "/autodiscover/autodiscover.json"
            version_url = url + "/EWS/Exchange.asmx"
            response = requests.get(autodiscovery_url, verify=False, timeout=5)
            host_name = response.headers.get("x-calculatedbetarget")
            response = requests.get(version_url, verify=False, timeout=5)
            exchange_version = response.headers.get("X-OWA-Version")
            
            if host_name:
                if host not in d:
                    d[host] = []
                d[host].append(f"Host Name: {host_name}")
                
            if exchange_version:
                if host not in d:
                    d[host] = []
                d[host].append(f"Exchange Version: {exchange_version}")
            
        except: continue
        
        if len(d) > 0:
            print("Exchange Server information:")
            for key, value in d.items():
                print(f"\t{key}:")
                for v in value:
                    print(f"\t\t{v}")
    pass
    

def check(directory_path, config, verbose, hosts = "hosts.txt"):
    check(directory_path, config, verbose, hosts)

def main():
    parser = argparse.ArgumentParser(description="Microsoft Exchange application module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args.verbose, args.filename or "hosts.txt")