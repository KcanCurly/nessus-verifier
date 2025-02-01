import subprocess
import re
import ssl
import socket
import argparse
from src.utilities.utilities import get_hosts_from_file
from src.services import smb

def entry_solver(args):
    solve(args.file)

def entry_cmd():
    parser = argparse.ArgumentParser(description="SMB Service Misconfigurations")
    parser.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    
    args = parser.parse_args()
    
    entry_solver(args)

def solve(hosts):
    smb.null_guest_access_check(hosts)
    smb.sign_check(hosts)
            
if __name__ == "__main__":
    entry_cmd()