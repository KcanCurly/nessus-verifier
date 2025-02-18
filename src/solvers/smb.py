from src.services import smb
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 5

def get_default_config():
    return """
["5"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="SMB Service Misconfigurations")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan: 
        print("No id found in json file")
        return
    
    hosts = scan.hosts
    smb.null_guest_access_check(hosts)
    smb.sign_check(hosts)
            
