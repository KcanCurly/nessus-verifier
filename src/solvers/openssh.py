from src.services import ssh
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 3)
    if not scan: 
        print("No id found in json file")
        return
    
    hosts = scan.hosts
    ssh.version_check(hosts)
            
