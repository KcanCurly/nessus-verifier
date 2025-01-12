import argparse
import configparser
import os
from pathlib import Path
import requests
from requests.packages import urllib3  
from src.utilities import get_hosts_from_file

# Suppress only the InsecureRequestWarning
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

exch_versions = {
    "15.2.1544.14" : "Exchange Server 2019 CU14 Nov24SUv2",
    "15.2.1544.13" : "Exchange Server 2019 CU14 Nov24SU",
    "15.2.1544.11" : "Exchange Server 2019 CU14 Apr24HU",
    "15.2.1544.9" : "Exchange Server 2019 CU14 Mar24SU",
    "15.2.1544.4" : "Exchange Server 2019 CU14 (2024H1)",
    "15.2.1258.39" : "Exchange Server 2019 CU13 Nov24SUv2",
    "15.2.1258.38" : "Exchange Server 2019 CU13 Nov24SU",
    "15.2.1258.34" : "Exchange Server 2019 CU13 Apr24HU",
    "15.2.1258.32" : "Exchange Server 2019 CU13 Mar24SU",
    "15.2.1258.28" : "Exchange Server 2019 CU13 Nov23SU",
    "15.2.1258.27" : "Exchange Server 2019 CU13 Oct23SU",
    "15.2.1258.25" : "Exchange Server 2019 CU13 Aug23SUv2",
    "15.2.1258.23" : "Exchange Server 2019 CU13 Aug23SU",
    "15.2.1258.16" : "Exchange Server 2019 CU13 Jun23SU",
    "15.2.1258.12" : "Exchange Server 2019 CU13 (2023H1)",
    "15.2.1118.40" : "Exchange Server 2019 CU12 Nov23SU",
    "15.2.1118.39" : "Exchange Server 2019 CU12 Oct23SU",
    "15.2.1118.37" : "Exchange Server 2019 CU12 Aug23SUv2",
    "15.2.1118.36" : "Exchange Server 2019 CU12 Aug23SU",
    "15.2.1118.30" : "Exchange Server 2019 CU12 Jun23SU",
    "15.2.1118.26" : "Exchange Server 2019 CU12 Mar23SU",
    "15.2.1118.25" : "Exchange Server 2019 CU12 Feb23SU",
    "15.2.1118.21" : "Exchange Server 2019 CU12 Jan23SU",
    "15.2.1118.20" : "Exchange Server 2019 CU12 Nov22SU",
    "15.2.1118.15" : "Exchange Server 2019 CU12 Oct22SU",
    "15.2.1118.12" : "Exchange Server 2019 CU12 Aug22SU",
    "15.2.1118.9" : "Exchange Server 2019 CU12 May22SU",
    "15.2.1118.7" : "Exchange Server 2019 CU12 (2022H1)",
    "15.2.986.42" : "Exchange Server 2019 CU11 Mar23SU",
    "15.2.986.41" : "Exchange Server 2019 CU11 Feb23SU",
    "15.2.986.37" : "Exchange Server 2019 CU11 Jan23SU",
    "15.2.986.36" : "Exchange Server 2019 CU11 Nov22SU",
    "15.2.986.30" : "Exchange Server 2019 CU11 Oct22SU",
    "15.2.986.29" : "Exchange Server 2019 CU11 Aug22SU",
    "15.2.986.26" : "Exchange Server 2019 CU11 May22SU",
    "15.2.986.22" : "Exchange Server 2019 CU11 Mar22SU",
    "15.2.986.15" : "Exchange Server 2019 CU11 Jan22SU",
    "15.2.986.14" : "Exchange Server 2019 CU11 Nov21SU",
    "15.2.986.9" : "Exchange Server 2019 CU11 Oct21SU",
    "15.2.986.5" : "Exchange Server 2019 CU11",
    "15.2.922.27" : "Exchange Server 2019 CU10 Mar22SU",
    "15.2.922.20" : "Exchange Server 2019 CU10 Jan22SU",
    "15.2.922.19" : "Exchange Server 2019 CU10 Nov21SU",
    "15.2.922.14" : "Exchange Server 2019 CU10 Oct21SU",
    "15.2.922.13" : "Exchange Server 2019 CU10 Jul21SU",
    "15.2.922.7" : "Exchange Server 2019 CU10",
    "15.2.858.15" : "Exchange Server 2019 CU9 Jul21SU",
    "15.2.858.12" : "Exchange Server 2019 CU9 May21SU",
    "15.2.858.10" : "Exchange Server 2019 CU9 Apr21SU",
    "15.2.858.5" : "Exchange Server 2019 CU9",
    "15.2.792.15" : "Exchange Server 2019 CU8 May21SU",
    "15.2.792.13" : "Exchange Server 2019 CU8 Apr21SU",
    "15.2.792.10" : "Exchange Server 2019 CU8 Mar21SU",
    "15.2.792.3" : "Exchange Server 2019 CU8",
    "15.2.721.13" : "Exchange Server 2019 CU7 Mar21SU",
    "15.2.721.2" : "Exchange Server 2019 CU7",
    "15.2.659.12" : "Exchange Server 2019 CU6 Mar21SU",
    "15.2.659.4" : "Exchange Server 2019 CU6",
    "15.2.595.8" : "Exchange Server 2019 CU5 Mar21SU",
    "15.2.595.3" : "Exchange Server 2019 CU5",
    "15.2.529.13" : "Exchange Server 2019 CU4 Mar21SU",
    "15.2.529.5" : "Exchange Server 2019 CU4",
    "15.2.464.15" : "Exchange Server 2019 CU3 Mar21SU",
    "15.2.464.5" : "Exchange Server 2019 CU3",
    "15.2.397.11" : "Exchange Server 2019 CU2 Mar21SU",
    "15.2.397.3" : "Exchange Server 2019 CU2",
    "15.2.330.11" : "Exchange Server 2019 CU1 Mar21SU",
    "15.2.330.5" : "Exchange Server 2019 CU1",
    "15.2.221.18" : "Exchange Server 2019 RTM Mar21SU",
    "15.2.221.12" : "Exchange Server 2019 RTM",
    "15.2.196.0" : "Exchange Server 2019 Preview"
}

cves = {
    
}

def host_name_exposure(directory_path, config, verbose, hosts = "hosts.txt"):
    hosts = get_hosts_from_file(hosts)
    l = []
    for host in hosts:
        try:
            url = f"https://{host}"
            autodiscovery_url = url + "/autodiscover/autodiscover.json"
            response = requests.get(autodiscovery_url, verify=False, timeout=5)
            l.append(f"{host} - {response.headers.get("x-calculatedbetarget")}")
        except: continue
    
    if len(l) > 0:
        print("Hostname Exposure:")
        for a in l:
            print(f"\n{a}")

def version_check(directory_path, config, verbose, hosts = "hosts.txt"):
    d = {}
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            url = f"https://{host}"
            version_url = url + "/EWS/Exchange.asmx"
            response = requests.get(version_url, verify=False, timeout=5)
            exchange_version = response.headers.get("X-OWA-Version")
                
            if exchange_version:
                if exchange_version not in d:
                    d[exchange_version] = []
                d[exchange_version].append(f"{host}")
            
        except: continue
        
    if len(d) > 0:
        print("Exchange Server information:")
        for key, value in d.items():
            print(f"\t{key}:")
            for v in value:
                print(f"\t\t{v}")
    

def check(directory_path, config, verbose, hosts = "hosts.txt"):
    host_name_exposure(directory_path, config, verbose, hosts)
    version_check(directory_path, config, verbose, hosts)

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