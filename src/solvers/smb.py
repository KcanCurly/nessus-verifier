from src.services import smb
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 5)
    if not scan: 
        print("No id found in json file")
        return
    
    hosts = scan.hosts
    smb.null_guest_access_check(hosts)
    smb.sign_check(hosts)
            
