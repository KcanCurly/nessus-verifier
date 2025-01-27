import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
from impacket.smb import SMB
from impacket.smbconnection import SMBConnection
from src.utilities import get_hosts_from_file

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts, False)
    null_vuln = {}
    guess_vuln = {}
    sign = []
    ntlmv1 = []
    
    for host in hosts:
        try:
            conn = SMBConnection(host, host)
            if not conn._SMBConnection.is_signing_required():
                sign.append(host)
            if not conn._SMBConnection.doesSupportNTLMv2():
                ntlmv1.append(host)
            conn.login('','')
            if host not in null_vuln:
                null_vuln[host] = []
            shares = conn.listShares()
            for s in shares:
                null_vuln[host].append(s['shi1_netname'][:-1])
            conn.logoff()
            
        except Exception :pass
        try:
            conn = SMBConnection(host, host)  
            conn.login('guest','')
            if host not in guess_vuln:
                guess_vuln[host] = []
            shares = conn.listShares()
            for s in shares:
                null_vuln[host].append(s['shi1_netname'][:-1])
            conn.logoff()
        except Exception :pass
        
    if len(null_vuln) > 0:
        print("Null session was possible on hosts:")
        for k,v in null_vuln.items():
            print(k)
            for z in v:
                print(f"\t{z}")
                
    if len(guess_vuln) > 0:
        print("Guest session was possible on hosts:")
        for k,v in guess_vuln.items():
            print(k)
            for z in v:
                print(f"\t{z}")
    
    if len(sign) > 0:
        print("SMB signing NOT enabled on hosts:")
        for v in sign:
            print(f"\t{v}")
            
    if len(ntlmv1) > 0:
        print("NTLMv1 supported on hosts:")
        for v in ntlmv1:
            print(f"\t{v}")

def main():
    parser = argparse.ArgumentParser(description="SMB module of nessus-verifier.")
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