import argparse
import configparser
import os
from pathlib import Path
from socket import timeout
import subprocess
import re
import time
from impacket.smbconnection import SMBConnection
from src.utilities import get_hosts_from_file
from smb import SMBConnection as pysmbconn

def check1(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts, False)
    
    null_vuln: dict = {}
    guess_vuln: dict = {}
    
    for host in hosts:
        # Get NetBIOS of the remote computer
        command = ["nmblookup", "-A", host]
        result = subprocess.run(command, text=True, capture_output=True)
        netbios_re = r"\s+(.*)\s+<20>"
        
        s = re.search(netbios_re, result.stdout)
        if s:
            nbname = s.group()
        
            try:
                conn = pysmbconn.SMBConnection('', '', '', nbname, is_direct_tcp=True)
                a = conn.connect(host, 445, timeout=3)
                shares = conn.listShares(timeout=3)
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        null_vuln[host] = []
                        try:
                            for file in files:
                                if file.filename == "." or file.filename == "..": continue
                                null_vuln[host].append(file.filename)
                        except Exception as e: pass
                    except Exception as e: pass
                
            except Exception as e: pass
            try:
                conn = pysmbconn.SMBConnection('guest', '', '', nbname, is_direct_tcp=True)
                a = conn.connect(host, 445, timeout=3)
                shares = conn.listShares(timeout=3)
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        guess_vuln[host] = []
                        try:
                            for file in files:
                                if file.filename == "." or file.filename == "..": continue
                                guess_vuln[host].append(file.filename)
                        except Exception as e: pass
                    except Exception as e: pass
                
            except Exception as e: pass
            
    if len(null_vuln) > 0:
        print("Null session accessible share on hosts:")
        for k,v in null_vuln.items():
            print(f"{k}:445")
            for z in v:
                print(f"\t{z}")
                
    if len(guess_vuln) > 0:
        print("Guest session accessible share on hosts:")
        for k,v in guess_vuln.items():
            print(f"{k}:445")
            for z in v:
                print(f"\t{z}")

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts, False)

    sign = []
    smbv1 = []
    for host in hosts:
        try:
            conn = SMBConnection(host, host, timeout=3)
            if not conn._SMBConnection.is_signing_required():
                sign.append(host)

            
        except Exception as e: print(e)

        try:
            conn = SMBConnection(host, host, timeout=3, preferredDialect="NT LM 0.12") 
            smbv1.append(host)
        except Exception:pass
        

    
    if len(sign) > 0:
        print("SMB signing NOT enabled on hosts:")
        for v in sign:
            print(f"\t{v}:445")
            
    if len(smbv1) > 0:
        print("SMBv1 enabled on hosts:")
        for v in smbv1:
            print(f"\t{v}:445")
            

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
        
    
    check1(args.directory or os.curdir, config, args, args.filename or "hosts.txt")