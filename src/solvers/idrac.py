from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
from src.services.idrac import version_nv
import requests

code = 19

def get_default_config():
    return """
["19"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="iDRAC")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_task1.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_task1.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_task1.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_task1.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_task1.set_defaults(func=solve) 
    

def solve(args, is_all = False):
    versions = {}
    
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
    
    version_nv(hosts, timeout=args.timeout, verbose=args.verbose, disable_visual_on_complete=args.disable_visual_on_complete, only_show_progress=args.only_show_progress)