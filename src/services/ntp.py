from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments
import nmap

class Mode6_Vuln_Data():
    def __init__(self, host: str, mods: list[str]):
        self.host = host
        self.mods = mods

def is_empty_or_spaces(s):
    return s.strip() == ""

def mode6_single(host, timeout, errors, verbose):
    try:
        nm = nmap.PortScanner()
        ip, port = host.split(":")
        nm.scan(hosts=ip, ports=port, arguments="--script=ntp-info -sU")
        for result in nm.all_hosts():
            if "udp" in nm[result] and 123 in nm[result]["udp"]:
                ntp_script = nm[result]["udp"][123].get("script", {})
                v = Mode6_Vuln_Data(host, [])
                for key, value in ntp_script.items():
                    v.mods.append(value)
                return v
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")


def mode6_nv(hosts, threads, timeout, errors, verbose):
    results: list[Mode6_Vuln_Data] = get_default_context_execution("NTP Mode 6 Usage", threads, hosts, (mode6_single, timeout, errors, verbose))

    if len(results) > 0:
        print("NTP Mode 6 Enabled Hosts:")
        for r in results:
            print(r.host)
        print("NTP Mode 6 Data:")
        for r in results:
            print(f"{r.host}:")
            for v in r.mods:
                if is_empty_or_spaces(v): continue
                print(f"    {v}")
                

def monlist_single(host, timeout, errors, verbose):
    try:
        nm = nmap.PortScanner()
        ip, port = host.split(":")
        nm.scan(hosts=ip, ports=port, arguments="--script=ntp-monlist -sU")
        for result in nm.all_hosts():
            if "udp" in nm[result] and 123 in nm[result]["udp"]:
                ntp_script = nm[result]["udp"][123].get("script", {})
                v = Mode6_Vuln_Data(host, [])
                for key, value in ntp_script.items():
                    v.mods.append(value)
                return v
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")

def monlist_nv(hosts, threads, timeout, errors, verbose):
    results: list[Mode6_Vuln_Data] = get_default_context_execution("NTP Mode 6 Usage", threads, hosts, (monlist_single, timeout, errors, verbose))
                
    if len(results) > 0:
        print("NTP monlist Enabled Hosts:")
        for r in results:
            print(r.host)
        print("NTP monlist Data:")
        for r in results:
            print(f"{r.host}:")
            for v in r.mods:
                if is_empty_or_spaces(v): continue
                print(f"    {v}")
        
def monlist_console(args):
    monlist_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)
    
def mode6_console(args):
    mode6_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)
    

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ntp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_mode6 = subparsers.add_parser("mode6", help="Checks if mode 6 supported")
    add_default_parser_arguments(parser_mode6)
    parser_mode6.set_defaults(func=mode6_console)
    
    parser_monlist = subparsers.add_parser("monlist", help="Checks if monlist command is enabled")
    add_default_parser_arguments(parser_monlist)
    parser_monlist.set_defaults(func=monlist_console)