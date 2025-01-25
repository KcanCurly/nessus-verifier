import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
import socket
from src.utilities import get_hosts_from_file

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    vuln = []
    
    request = b'\x17\x00\x03\x2a' + b'\x00' * 40
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(10)
                s.sendto(request, (ip, int(port)))
                data, addr = s.recvfrom(1024)
                print(f"Received {len(data)} bytes from {addr}")
                print(data)
                vuln.append(host)
            
        except Exception as e: print(e)
    
    if len(vuln) > 0:
        print("NTP service monlist enabled on hosts:")
        for v in vuln:
            print(f"\t{v}")
        

def main():
    parser = argparse.ArgumentParser(description="NTP module of nessus-verifier.")
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