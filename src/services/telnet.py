import nmap
from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments

def version_single(host, timeout, errors, verbose):
    try:
        nm = nmap.PortScanner()
        ip, port = host.split(":")
        nm.scan(ip, port, arguments=f'-sV')
        
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'telnet' in nmap_host['tcp'][int(port)]['name'].lower():
                product = nmap_host['tcp'][int(port)].get("product", "Service not found")
                return f"{host}{f" - {product}" if product else ""}"
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")

def version_nv(hosts, threads, timeout, errors, verbose):
    results = get_default_context_execution("Telnet Usage", threads, hosts, (version_single, timeout, errors, verbose))
    
    if len(results) > 0:
        print("Telnet Usage Detected:")
        for value in results:
            print(f"{value}")


def version_console(args):
    version_nv(get_hosts_from_file(args.target, False), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("telnet")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_usage = subparsers.add_parser("usage", help="Checks usage and product if possible")
    add_default_parser_arguments(parser_usage)
    parser_usage.set_defaults(func=version_console)