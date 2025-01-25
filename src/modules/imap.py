import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
import imaplib
import socket
from src.utilities import get_hosts_from_file

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    vuln = []
    
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            mail = imaplib.IMAP4_SSL(ip, int(port))
            print(f"SSL Connection to {ip}:{port} was a success")
            
        except Exception as e: print(e)
    
    if len(vuln) > 0:
        print("NTP service monlist enabled on hosts:")
        for v in vuln:
            print(f"\t{v}")
        

def main():
    parser = argparse.ArgumentParser(description="IMAP module of nessus-verifier.")
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