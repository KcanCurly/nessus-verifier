from src.services import ssh
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 3

def get_default_config():
    return """
["3"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="SSH Service Misconfigurations")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)
    
def solve(args, is_all = False):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan: 
        print("No id found in json file")
        return
    
    hosts = scan.hosts
    ssh.audit_nv(hosts)
            
