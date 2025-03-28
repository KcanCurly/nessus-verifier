import nmap
import socket
from src.utilities.utilities import Version_Vuln_Data, get_hosts_from_file, get_default_context_execution, add_default_parser_arguments

def banner_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))

        response = b""  # Use bytes to handle binary data safely
        while True:
            chunk = s.recv(1024)  # Read in 1024-byte chunks
            if not chunk:  # If empty, connection is closed
                break
            response += chunk  # Append to response

        response = response.decode(errors="ignore")

        # Close the connection
        s.close()
        
        return Version_Vuln_Data(host, response)
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
        
def banner_nv(hosts, threads, timeout, errors, verbose):
    results: list[Version_Vuln_Data] = get_default_context_execution("Telnet Banner Grab", threads, hosts, (banner_single, timeout, errors, verbose))

    if results and len(results) > 0:
        print("Telnet Banners:")
        for r in results:
            print("=================================")
            print(r.host)
            print("=================================")
            print(r.version)
        
def banner_console(args):
    banner_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

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
    
    if results and len(results) > 0:
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
    
    parser_banner = subparsers.add_parser("banner", help="Banner Grab")
    add_default_parser_arguments(parser_banner)
    parser_banner.set_defaults(func=banner_console)