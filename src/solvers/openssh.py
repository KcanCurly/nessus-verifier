from src.services import ssh
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

def helper_parse(subparser):
    parser_task1 = subparser.add_parser("14", help="OpenSSH Versions")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 3)
    if not scan: 
        print("No id found in json file")
        return
    
    hosts = scan.hosts
    ssh.version_nv(hosts)
            
