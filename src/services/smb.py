import argparse
from ast import List
import configparser
import os
from pathlib import Path
import subprocess
import re
from impacket.smbconnection import SMBConnection
from src.utilities import get_hosts_from_file
from smb import SMBConnection as pysmbconn

def null_guest_access_check(hosts: list[str], verbose = False, debug = False):
    null_vuln: dict = {}
    null_vuln_files: dict = {}
    guest_vuln: dict = {}
    guest_vuln_files: dict = {}
    
    null_vuln: dict = {}
    null_vuln_files: dict = {}
    guest_vuln: dict = {}
    guest_vuln_files: dict = {}
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        
        # Get NetBIOS of the remote computer
        command = ["nmblookup", "-A", ip]
        result = subprocess.run(command, text=True, capture_output=True)
        netbios_re = r"\s+(.*)\s+<20>"
        
        s = re.search(netbios_re, result.stdout)
        if s:
            nbname = s.group()
        
            try:
                conn = pysmbconn.SMBConnection('', '', '', nbname, is_direct_tcp=True)
                if not conn.connect(ip, int(port), timeout=3): continue
                shares = conn.listShares(timeout=3)
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        null_vuln[host] = []
                        null_vuln[host].append(share.name)
                        null_vuln_files[share.name] = []
                        try:
                            for file in files:
                                if file.filename == "." or file.filename == "..": continue
                                null_vuln_files[share.name].append(file.filename)
                        except Exception as e: pass
                    except Exception as e: pass
                
            except Exception as e: pass
            try:
                conn = pysmbconn.SMBConnection('guest', '', '', nbname, is_direct_tcp=True)
                if not conn.connect(ip, int(port), timeout=3): continue
                shares = conn.listShares(timeout=3)
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        guest_vuln[host] = []
                        guest_vuln[host].append(share.name)
                        guest_vuln_files[share.name] = []
                        try:
                            for file in files:
                                if file.filename == "." or file.filename == "..": continue
                                guest_vuln_files[share.name].append(file.filename)
                        except Exception as e: pass
                    except Exception as e: pass
                
            except Exception as e: pass
            
    if len(null_vuln) > 0:
        print("Null session accessible share on hosts:")
        for k,v in null_vuln.items():
            print(f"{k}")
            for z in v:
                print(f"\t{z}")
                for zz in null_vuln_files[z]:
                    print(f"\t\t{zz}")
                
    if len(guest_vuln) > 0:
        print("Guest session accessible share on hosts:")
        for k,v in guest_vuln.items():
            print(f"{k}")
            for z in v:
                print(f"\t{z}")
                for zz in guest_vuln_files[z]:
                    print(f"\t\t{zz}")

def sign_check(hosts: list[str], verbose = False, debug = False):
    sign = []
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        
        try:
            conn = SMBConnection(ip, ip, sess_port=int(port),timeout=3)
            if not conn._SMBConnection.is_signing_required():
                sign.append(host)
        except Exception:pass
    
    if len(sign) > 0:
        print("SMB signing NOT enabled on hosts:")
        for v in sign:
            print(f"\t{host}")
            

        
def smbv1_check(hosts: list[str], verbose = False, debug = False):
    smbv1 = []
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        try:
            SMBConnection(ip, ip, sess_port=int(port), timeout=3, preferredDialect="NT LM 0.12") 
            smbv1.append(host)
        except Exception:pass
    
    if len(smbv1) > 0:
        print("SMBv1 enabled on hosts:")
        for v in smbv1:
            print(f"\t{host}")

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    null_guest_access_check(hosts)
    sign_check(hosts)
    smbv1_check(hosts)

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