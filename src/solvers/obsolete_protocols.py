from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
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
            nm.scan(ip, "7,9,13,17,19", arguments=f'-sV')
            
            if ip in nm.all_hosts():
                nmap_host = nm[ip]
                if nmap_host.has_tcp(7) and nmap_host['tcp'][7]['state'] == 'open' and nmap_host['tcp'][7]['name'].lower() == 'echo':
                    vuln_echo.append(host)
                if nmap_host.has_tcp(9) and nmap_host['tcp'][9]['state'] == 'open' and nmap_host['tcp'][9]['name'].lower() == 'discard':
                    vuln_discard.append(host)
                if nmap_host.has_tcp(13) and nmap_host['tcp'][13]['state'] == 'open' and nmap_host['tcp'][13]['name'].lower() == 'daytime':
                    vuln_daytime.append(host)
                if nmap_host.has_tcp(17) and nmap_host['tcp'][17]['state'] == 'open' and nmap_host['tcp'][17]['name'].lower() == 'qotd':
                    vuln_qotd.append(host)
                if nmap_host.has_tcp(19) and nmap_host['tcp'][19]['state'] == 'open' and nmap_host['tcp'][19]['name'].lower() == 'chargen':
                    vuln_chargen.append(host)
                    
        except: pass
    
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
