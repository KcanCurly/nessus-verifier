from src.utilities.utilities import find_scan, add_default_parser_arguments, add_default_solver_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput
from src.services.ftp import anon_nv

code = 31

def get_default_config():
    return """
["31"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="FTP")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
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
    anon_nv(hosts, args.threads, args.timeout, args.errors, args.verbose)
    
    