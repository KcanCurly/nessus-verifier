import socket
import struct
import time
from src.utilities.utilities import get_hosts_from_file


def usage_nv(hosts, error: bool, verbose: bool):
    vuln = {}    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        try:
        # Create a socket for the Time Protocol (TCP)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)  # Set a timeout for the connection
                s.connect((ip, int(port)))  # Connect to the server
                
                # Receive the 4-byte binary time response
                data = s.recv(4)
                if len(data) != 4:
                    if error: print("Invalid response length.")
                    return
                
                # Unpack the 4-byte response as an unsigned integer
                server_time = struct.unpack("!I", data)[0]
                
                # Convert the server time to seconds since the Unix epoch
                unix_time = server_time - 2208988800  # Subtract Time Protocol epoch (1900) offset
                
                # Display the time in human-readable format
                vuln[host] = f"{time.ctime(unix_time)}"
        except socket.timeout:
            print("Connection timed out.")
            pass
        except Exception as e:
            print(f"An error occurred: {e}")
            pass
    
    if len(vuln):
        print("Time protocol detected:")
        for k,v in vuln.items():
            print(f"    {k} -> {v}")

def usage_console(args):
    usage_nv(get_hosts_from_file(args.file))

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("time")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    brute_parser = subparsers.add_parser("usage", help="Checks Time protocol usage")
    brute_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    brute_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    brute_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    brute_parser.set_defaults(func=usage_console)
    