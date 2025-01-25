import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
import imaplib
import socket
import ssl
from src.utilities import get_hosts_from_file

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    tls_enabled = []
    vuln = []
    tls_not_forced = []
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            mail = imaplib.IMAP4_SSL(ip, int(port), timeout=3)
            tls_enabled.append(host)

        except ssl.SSLError: vuln.append(host)
        except Exception:pass
    
    for host in tls_enabled:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            mail = imaplib.IMAP4(ip, int(port), 3)
            tls_not_forced.append(host)

        except Exception:pass
    
    if len(vuln) > 0:
        print("TLS NOT enabled on hosts:")
        for v in vuln:
            print(f"\t{v}")
    
    if len(tls_not_forced) > 0:
        print("TLS is enabled but NOT forced on hosts:")
        for v in tls_not_forced:
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