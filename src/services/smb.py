import argparse
import configparser
import os
from pathlib import Path
from impacket.smbconnection import SMBConnection
from src.utilities import get_hosts_from_file

def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts, False)
    null_vuln = {}
    guess_vuln = {}
    sign = []
    smbv1 = []
    
    for host in hosts:
        try:
            conn = SMBConnection(host, host, timeout=3)

            if not conn._SMBConnection.is_signing_required():
                sign.append(host)
            conn.login('','')
            shares = conn.listShares()

            if host not in null_vuln:
                null_vuln[host] = []
            for s in shares:
                conn.connectTree(s['shi1_netname'])
                conn.listPath(s['shi1_netname'], "/")
                null_vuln[host].append(s['shi1_netname'][:-1])
            conn.logoff()
            
        except Exception as e: print(e)
        try:
            conn = SMBConnection(host, host, timeout=3) 
            conn.login('guest','')
            shares = conn.listShares()

            for s in shares:
                try:
                    print(s['shi1_netname'][:-1])
                    conn.connectTree(s['shi1_netname'][:-1])
                    conn.listPath(s['shi1_netname'][:-1], "/")
                    if host not in guess_vuln:
                        guess_vuln[host] = []
                    print("pain")
                    print(s['shi1_netname'])
                    guess_vuln[host].append(s['shi1_netname'][:-1])
                except Exception as e: print(e)
            conn.logoff()
        except Exception as e: print(e)
        
        try:
            conn = SMBConnection(host, host, timeout=3, preferredDialect="NT LM 0.12") 
            smbv1.append(host)
        except Exception:pass
        
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
        
    
    check(args.directory or os.curdir, config, args, args.filename or "hosts.txt")