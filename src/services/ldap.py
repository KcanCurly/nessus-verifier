import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
import ssl
from ldap3 import Server, Connection, ALL, Tls
from ldap3.core.exceptions import LDAPBindError
from src.utilities import get_hosts_from_file


def check(directory_path, config, args, hosts):
    hosts = get_hosts_from_file(hosts)
    vuln = []
    tls_conf = Tls(validate=ssl.CERT_NONE)
    
    for host in hosts:        
        try:
            server = Server(f'ldap://{host}')
            conn = Connection(server, user=None, password=None, auto_bind=True)
            vuln.append(host)
        except LDAPBindError:
            try:
                server = Server(f'ldaps://{host}', user=None, password=None, auto_bind=True, tls=tls_conf)
                conn = Connection(server, user=None, password=None, auto_bind=True)
                vuln.append(f"{host} (TLS)")
            except: pass
        except:pass
    
    if len(vuln) > 0:
        print("LDAP anonymous access were found:")
        for v in vuln:
            print(f"\t{v}")
        

def main():
    parser = argparse.ArgumentParser(description="LDAP module of nessus-verifier.")
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