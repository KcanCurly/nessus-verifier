from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments
from src.modules.nv_parse import GroupNessusScanOutput
import nmap

code = 18

def get_default_config():
    return """
["18"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Obsolete Protocols")
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
    

    vuln_echo = []
    vuln_discard = []
    vuln_daytime = []
    vuln_qotd = []
    vuln_chargen = []
    vuln_systat = []

    nm = nmap.PortScanner()
    for host in hosts:
        try:
            ip, port = host.split(":")
            nm.scan(ip, port, arguments=f'-sV')
            
            if ip in nm.all_hosts():
                nmap_host = nm[ip]
                print(nmap_host)
                if nmap_host.has_tcp(int(port)) and nmap_host['tcp'][int(port)]['state'] == 'open':
                    n = nmap_host['tcp'][int(port)]['name'].lower()
                    if 'echo' in n:
                        vuln_echo.append(host)
                    elif 'discard' in n:
                        vuln_discard.append(host)
                    elif 'daytime' in n:
                        vuln_daytime.append(host)
                    elif 'qotd' in n:
                        vuln_qotd.append(host)
                    elif 'chargen' in n:
                        vuln_chargen.append(host)
                    elif 'systat' in n:
                        vuln_systat.append(host)
                                    
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
            
    if len(vuln_systat) > 0:
        print("Systat Protocol Detected:")
        for value in vuln_systat:
            print(f"{value}")
