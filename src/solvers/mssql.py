from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import re
import nmap

code = 16

def get_default_config():
    return """
["16"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="MSSQL Version")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 

def solve(args, is_all = False):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan: 
        print("No id found in json file")
        return
    
    r = r"nginx/(.*)"
    
    hosts = scan.hosts
    
    nm = nmap.PortScanner()
    
    
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            nm.scan(ip, port, arguments=f'--script ms-sql-info')
            
            if ip in nm.all_hosts():
                nmap_host = nm[ip]
                if 'tcp' in nmap_host and 1433 in nmap_host['tcp']:
                    tcp_info = nmap_host['tcp'][1433]
                    if 'script' in tcp_info and 'ms-sql-info' in tcp_info['script']:
                        # Extract the ms-sql-info output
                        ms_sql_info = tcp_info['script']['ms-sql-info']

                        # Parse the output to get product name and version
                        product_name = None
                        version_number = None

                        # Look for product and version in the output
                        for line in ms_sql_info.splitlines():
                            if "Product:" in line:
                                product_name = line.split(":")[1].strip()
                            if "number:" in line:
                                version_number = line.split(":")[1].strip()

                        # Print the results
                        if product_name and version_number:
                            z = product_name + " " + version_number
                            if z not in versions:
                                versions[z] = set()
                            versions[z].add(host)
        except Exception as e: pass #print(e)


    
    if len(versions) > 0:
        print("Detected MSSQL Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")