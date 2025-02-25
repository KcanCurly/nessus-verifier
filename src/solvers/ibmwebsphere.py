import argparse
import subprocess
import re
from impacket.smbconnection import SMBConnection
from src.utilities.utilities import get_hosts_from_file
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.services.service import Vuln_Data
from rich.console import Group
from rich.panel import Panel
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import requests

code = 29

def get_default_config():
    return """
["29"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="IBM WebSphere Version")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve) 
    
def solve(args):
    l= logger.setup_logging(args.verbose)

    hosts = []
    if args.file:
        scan: GroupNessusScanOutput = find_scan(args.file, code)
        if not scan: 
            if is_all: return
            if not args.ignore_fail: print("No id found in json file")
            return
        hosts = scan.hosts
    elif args.list_file:
        with open(args.list_file, 'r') as f:
            hosts = [line.strip() for line in f]
            
    versions = {}
    r = r"<title>WebSphere Application Server V(.*)</title>"
    liberty = r"<title>WebSphere Liberty (.*)</title>"
    
    for host in hosts:
            try:
                try:
                    resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
                except Exception:
                    try:
                        resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
                    except: continue
                
                m = re.search(r, resp.text)
                if m:
                    version = m.group(1)
                    version = f"WebSphere Application Server {version}"
                    if version not in versions:
                        versions[version] = set()
                    versions[version].add(host)
                    
                else:
                    m = re.search(liberty, resp.text)
                    if m:
                        version = m.group(1)
                        version = f"WebSphere Liberty {version}"
                        if version not in versions:
                            versions[version] = set()
                        versions[version].add(host)
                    
                
            except Exception: pass
            
    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Detected IBM WebSphere Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
        