from src.utilities.utilities import find_scan, get_header_from_url
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import re
import nmap

def helper_parse(subparser):
    parser_task1 = subparser.add_parser("16", help="MSSQL Version")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve) 

def solve(args):
    versions = {}
    
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, 16)
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
                            print(line)
                            if "Product:" in line:
                                
                                product_name = line.split(":")[1].strip()
                            if "Version:" in line:
                                version_number = line.split(":")[1].strip()

                        # Print the results
                        if product_name and version_number:
                            z = product_name + " " + version_number
                            if z not in versions:
                                versions[z] = set()
                            versions[z].add(host)
                        else:
                            print("Product or version information not found.")
                    else:
                        print("ms-sql-info script did not return any data.")
                else:
                    print("Port 1433 is not open or not running MSSQL.")
            else:
                print(f"Host {host} is not reachable or did not respond to the scan.")
        except Exception as e: print(e)
        header = get_header_from_url(host, "Server")
        if header:
            m = re.search(r, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                m = "nginx " + m
                if m not in versions:
                    versions[m] = set()
                versions[m].add(host)

    
    if len(versions) > 0:
        print("Detected Ngnix Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")