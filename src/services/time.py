import socket
import struct
import time
from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments, get_default_context_execution

def usage_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)  # Set a timeout for the connection
            s.connect((ip, int(port)))  # Connect to the server
            
            # Receive the 4-byte binary time response
            data = s.recv(4)
            if len(data) != 4:
                if errors: print(f"Error for {host} - Invalid response length.")
                return
            
            # Unpack the 4-byte response as an unsigned integer
            server_time = struct.unpack("!I", data)[0]
            
            # Convert the server time to seconds since the Unix epoch
            unix_time = server_time - 2208988800  # Subtract Time Protocol epoch (1900) offset
            
            # Display the time in human-readable format
            return f"{host} - {time.ctime(unix_time)}"
    except Exception as e:
        if errors: print(f"Error for {host} - {e}")

def usage_nv(hosts, threads, timeout, errors, verbose):
    results: list[str] = get_default_context_execution("Time Protocol Usage", threads, hosts, (usage_single, timeout, errors, verbose))

    if len(results):
        print("Time protocol detected:")
        for r in results:
            print(f"    {r}")

def usage_console(args):
    usage_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("time")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_usage = subparsers.add_parser("usage", help="Checks Time protocol usage")
    add_default_parser_arguments(parser_usage)
    parser_usage.set_defaults(func=usage_console)
    