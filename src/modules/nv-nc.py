from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2, Version_Vuln_Host_Data
import nmap
import argparse
import socket

@error_handler(["host"])
def connect_and_get_response_single(host, **kwargs):
    timeout = kwargs.get("timeout", 3)  # Default timeout is 3 seconds

    with socket.create_connection((host.ip, int(host.port)), timeout=timeout) as sock:
        sock.settimeout(timeout)

        try:
            response = sock.recv(1024)  # Try receiving data
            if response:
                return response.decode().strip()
        except socket.timeout:
            pass  # No response within timeout

        # If no response, send "info"
        sock.sendall(b"info\n")

        response = sock.recv(1024)  # Receive response after sending "info"
        return Version_Vuln_Host_Data(host, response.decode().strip())


    
def connect_and_get_response_multiple(hosts, output, message, threads, timeout):
    hosts = get_hosts_from_file2(hosts)
    results: list[Version_Vuln_Host_Data] = get_default_context_execution2("banner grab", threads, hosts, connect_and_get_response_single, timeout=timeout)
    
    for result in results:
        print(result.host)
        print("" * 20)
        print()
        print(result.version)
        print()
        print()


def main():
    parser = argparse.ArgumentParser(description="Connecto r to a list of hosts and get their service information.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    parser.add_argument("--message", type=str, default="info", help="Message to send for bannger grab.")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout for socket connection (default: 3 seconds).")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    args = parser.parse_args()
    
    connect_and_get_response_multiple(get_hosts_from_file2(args.file), args.output if args.output else None, args.message, args.threads, args.timeout)