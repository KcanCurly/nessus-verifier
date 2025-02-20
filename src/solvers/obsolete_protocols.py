from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
import tomllib
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import nmap
import requests

code = 18

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Obsolete Protocols")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve)

def solve(args, is_all = False):
    l= logger.setup_logging(args.verbose)
    hosts = []
    if args.file:
        scan: GroupNessusScanOutput = find_scan(args.file, code)
        if not scan: 
            if not args.ignore_fail: print("No id found in json file")
            return
        hosts = scan.hosts
    elif args.list_file:
        with open(args.list_file, 'r') as f:
            hosts = [line.strip() for line in f]
    
    if args.config:
        with open(args.config, "rb") as f:
            data = tomllib.load(f)