from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
import nmap

code = 18

def get_default_config():
    return """
["18"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Obsolete Protocols")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve)

def solve(args, is_all = False):
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
    

    vuln_echo = []
    vuln_discard = []
    vuln_daytime = []
    vuln_qotd = []
    vuln_chargen = []

    nm = nmap.PortScanner()
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            nm.scan(ip, port, arguments=f'-sV')
            
            if ip in nm.all_hosts():
                nmap_host = nm[ip]
                print(nmap_host)
                if nmap_host.has_tcp(int(port)) and nmap_host['tcp'][int(port)]['state'] == 'open':
                    if nmap_host['tcp'][int(port)]['name'].lower() == 'echo':
                        vuln_echo.append(host)
                    elif nmap_host['tcp'][int(port)]['name'].lower() == 'discard':
                        vuln_discard.append(host)
                    elif nmap_host['tcp'][int(port)]['name'].lower() == 'daytime':
                        vuln_daytime.append(host)
                    elif nmap_host['tcp'][int(port)]['name'].lower() == 'qotd':
                        vuln_qotd.append(host)
                    elif nmap_host['tcp'][int(port)]['name'].lower() == 'chargen':
                        vuln_chargen.append(host)
                                    
        except:pass
    
    if len(vuln_echo) > 0:
        print("Echo Protocol Detected:")
        for value in vuln_echo:
            print(f"{value}")
            
    if len(vuln_discard) > 0:
        print("Discard Protocol Detected:")
        for value in vuln_discard:
            print(f"{value}")
            
    if len(vuln_daytime) > 0:
        print("Daytime Protocol Detected:")
        for value in vuln_daytime:
            print(f"{value}")
            
    if len(vuln_qotd) > 0:
        print("QOTD Protocol Detected:")
        for value in vuln_qotd:
            print(f"{value}")
            
    if len(vuln_chargen) > 0:
        print("Chargen Protocol Detected:")
        for value in vuln_chargen:
            print(f"{value}")
