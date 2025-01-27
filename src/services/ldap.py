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
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            command = ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "(objectClass=*)"]
            result = subprocess.run(command, text=True, capture_output=True)
            if "ldaperr" not in result.stdout.lower():
                vuln.append(host)
        except Exception as e:print(e)
    
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