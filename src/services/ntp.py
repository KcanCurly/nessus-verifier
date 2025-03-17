from src.utilities.utilities import get_hosts_from_file
import nmap

def mode6_nv(hosts, timeout, errors, verbose):
    vuln = {}
    nm = nmap.PortScanner()
    for host in hosts:
        ip, port = host.split(":")
        nm.scan(hosts=ip, ports=port, arguments="--script=ntp-info -sU")
        for result in nm.all_hosts():
            if "udp" in nm[host] and 123 in nm[host]["udp"]:
                vuln[host] = []
                ntp_script = nm[host]["udp"][123].get("script", {})
                for key, value in ntp_script.items():
                    vuln[host].append(f"{key}: {value}")
                    
    if len(vuln) > 0:
        print("NTP Mode 6 Scanner:")
        for key, value in vuln.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
                

def monlist_nv(hosts, timeout, errors, verbose):
    vuln = {}
    nm = nmap.PortScanner()
    for host in hosts:
        ip, port = host.split(":")
        nm.scan(hosts=ip, ports=port, arguments="--script=ntp-monlist -sU")
        for result in nm.all_hosts():
            if "udp" in nm[host] and 123 in nm[host]["udp"]:
                vuln[host] = []
                ntp_script = nm[host]["udp"][123].get("script", {})
                for key, value in ntp_script.items():
                    vuln[host].append(f"{key}: {value}")
                    
    if len(vuln) > 0:
        print("NTP monlist Enabled:")
        for key, value in vuln.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
        
def monlist_console(args):
    monlist_nv(get_hosts_from_file(args.file), args.timeout, args.errors, args.verbose)
    
def mode6_console(args):
    mode6_nv(get_hosts_from_file(args.file), args.timeout, args.errors, args.verbose)
    

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ntp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_mode6 = subparsers.add_parser("mode6", help="Checks if mode 6 supported")
    parser_mode6.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_mode6.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_mode6.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_mode6.set_defaults(func=mode6_console)
    
    parser_monlist = subparsers.add_parser("monlist", help="Checks if monlist command is enabled")
    parser_monlist.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_monlist.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_monlist.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_monlist.set_defaults(func=monlist_console)