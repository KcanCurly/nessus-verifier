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
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan and not args.ignore_fail: 
        print("No id found in json file")
        return
    
    if args.config:
        with open(args.config, "rb") as f:
            data = tomllib.load(f)