import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
from impacket.smb import SMB
from impacket.smbconnection import SMBConnection
from src.utilities import get_hosts_from_file

def check(directory_path, hosts):
    if os.path.exists(os.path.join(directory_path, hosts)):
        print("Rlogin (CVE-1999-0651):")
        with open(os.path.join(directory_path, hosts), "r") as file:
            for line in file:
                print(f"\t{line}")

def main():
    parser = argparse.ArgumentParser(description="Rlogin module of nessus-verifier.")
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