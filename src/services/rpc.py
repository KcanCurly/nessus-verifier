import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
import socket
from src.utilities import get_hosts_from_file

pipes = [
    "LSARPC:lsaenumsid",
    "SAMR:enumdomains",
    "SPOOLSS:getjob",
    "SRVSVC:srvinfo",
    "DFS:dfsversion",
    "WKSSVC:wkssvc_wkstagetinfo",
    "NTSVCS:ntsvcs_getversion",
    "DRSUAPI:dsgetdcinfo",
    "EVENTLOG:eventlog_loginfo",
    "WINREG:winreg_enumkey",
    "FSRVP:fss_get_sup_version",
    ]

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    vuln = {}
    
    for host in hosts:

        ip = host.split(":")[0]
        port = host.split(":")[1]
        
        for pipe in pipes:
            name = pipe.split(":")[0]
            cmd = pipe.split(":")[1]
            try:
        
                command = ["rpcclient", "-N", "-U", "","-c", cmd, ip]
                result = subprocess.run(command, text=True, capture_output=True)
                
                if "nt_status" not in result.stderr.lower():
                    if host not in vuln:
                        vuln[host] = []
                    vuln[host].append(name)
            except:pass
                
    
    if len(vuln) > 0:
        print("Anonymous RPC pipes detected:")
        for k,v in vuln.items():
            print(f"{k} - {", ".join(v)}")
        

def main():
    parser = argparse.ArgumentParser(description="RPC module of nessus-verifier.")
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