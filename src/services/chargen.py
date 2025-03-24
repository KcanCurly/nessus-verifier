from src.utilities.utilities import Version_Vuln_Data, get_hosts_from_file, get_default_context_execution, add_default_parser_arguments
import socket

def banner_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))

        response = s.recv(256)  # Use bytes to handle binary data safely
        response = response.decode(errors="ignore")

        # Close the connection
        s.close()
        if len(response) > 0: return Version_Vuln_Data(host, response)
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
        
def banner_nv(hosts, threads, timeout, errors, verbose):
    results: list[Version_Vuln_Data] = get_default_context_execution("Chargen Banner Grab", threads, hosts, (banner_single, timeout, errors, verbose))

    if results and len(results) > 0:
        print("Chargen Banners:")
        for r in results:
            print("=================================")
            print(r.host)
            print("=================================")
            print(r.version)
        
def banner_console(args):
    banner_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def usage_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))

        response = s.recv(256)  # Use bytes to handle binary data safely
        response = response.decode(errors="ignore")

        # Close the connection
        s.close()

        if len(response) > 0: return host
    except Exception as e:
        response = response.decode(errors="ignore")
        year = response.split()[-1]
        if 1000 < year < 9999: return host
        if errors: print(f"Error for {host}: {e}")
        
def usage_nv(hosts, threads, timeout, errors, verbose):
    results = get_default_context_execution("Chargen Usage", threads, hosts, (usage_single, timeout, errors, verbose))
    
    if results and len(results) > 0:
        print("Chargen Usage Detected:")
        for value in results:
            print(f"{value}")

def usage_console(args):
    usage_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("chargen")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_usage = subparsers.add_parser("usage", help="Checks usage")
    add_default_parser_arguments(parser_usage)
    parser_usage.set_defaults(func=usage_console)
    
    parser_usage = subparsers.add_parser("banner", help="Banner Grab")
    add_default_parser_arguments(parser_usage)
    parser_usage.set_defaults(func=banner_console)