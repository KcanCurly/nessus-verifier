import subprocess
import re
import ssl
import socket
import argparse
from src.utilities.utilities import get_hosts_from_file
from src.services import ssh
from src.modules import vuln_parse

def entry_json_solver(v: vuln_parse.GroupNessusScanOutput):
    pass

def entry_solver(args):
    solve(args)

def entry_cmd():
    parser = argparse.ArgumentParser(description="SSH Service Misconfigurations")
    parser.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    
    args = parser.parse_args()
    
    entry_solver(args)

def solve(args):
    hosts = get_hosts_from_file(args.file)
    ssh.ssh_audit_check(hosts)
            
if __name__ == "__main__":
    entry_cmd()