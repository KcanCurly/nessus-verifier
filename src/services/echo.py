from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments
import socket

def usage_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))
        s.sendall(b"pentest")
        response = b""  # Use bytes to handle binary data safely
        while True:
            chunk = s.recv(1024)  # Read in 1024-byte chunks
            if len(chunk) < 1:  # If empty, connection is closed
                break
            response += chunk  # Append to response

        response = response.decode(errors="ignore")

        # Close the connection
        s.close()
        
        if response == "pentest": return host
    except Exception as e:
        response = response.decode(errors="ignore")
        if response == "pentest": return host
        if errors: print(f"Error for {host}: {e}")
        
def usage_nv(hosts, threads, timeout, errors, verbose):
    results = get_default_context_execution("Echo Usage", threads, hosts, (usage_single, timeout, errors, verbose))
    
    if results and len(results) > 0:
        print("Echo Usage Detected:")
        for value in results:
            print(f"{value}")

def usage_console(args):
    usage_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("echo")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_usage = subparsers.add_parser("usage", help="Checks usage")
    add_default_parser_arguments(parser_usage)
    parser_usage.set_defaults(func=usage_console)