from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2, Version_Vuln_Host_Data
import argparse, argcomplete
import socket
import ssl

@error_handler(["host"])
def connect_and_get_response_single(host, **kwargs):
    timeout = kwargs.get("timeout", 3)  # Default timeout is 3 seconds
    message = kwargs.get("message", "info")
    use_ssl = kwargs.get("ssl", False)
    print(use_ssl)
    use_ssl = True if use_ssl == "ssl" else False

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    if use_ssl:
        context = ssl._create_unverified_context()
        sock = context.wrap_socket(sock, server_hostname=host)

    sock.connect((host.ip, int(host.port)))

    try:
        response = sock.recv(1024)  # Try receiving data
        if response:
            return Version_Vuln_Host_Data(host, response.decode().strip())
    except socket.timeout:
        pass  # No response within timeout

    # If no response, send "info"
    sock.sendall(bytes(message))

    response = sock.recv(1024)  # Receive response after sending "info"
    return Version_Vuln_Host_Data(host, response.decode().strip())

    
def connect_and_get_response_multiple(hosts, output, message, ssl, threads, timeout):
    results: list[Version_Vuln_Host_Data] = get_default_context_execution2("banner grab", threads, hosts, connect_and_get_response_single, ssl=ssl, message=message, timeout=timeout)
    
    for result in results:
        print(result.host)
        print("" * 20)
        print()
        print(result.version)
        print()
        print()

    if output:
        with open(output, "w") as f:
            for result in results:
                print(result.host, file=f)
                print("" * 20, file=f)
                print("", file=f)
                print(result.version, file=f)
                print("", file=f)
                print("", file=f)


def main():
    parser = argparse.ArgumentParser(description="Connecto r to a list of hosts and get their service information.")
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    parser_normal = subparsers.add_parser("normal", help="Runs without ssl")
    parser_normal.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser_normal.add_argument("-o", "--output", type=str, default="nv-nc-output.txt", help="Output file. (Default: nv-nc-ssl-output.txt)")
    parser_normal.add_argument("--message", type=str, default="info", help="Message to send for bannger grab.")
    parser_normal.add_argument("--timeout", type=int, default=3, help="Timeout for socket connection (default: 3 seconds).")
    parser_normal.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")

    parser_ssl = subparsers.add_parser("ssl", help="Runs with ssl")
    parser_ssl.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser_ssl.add_argument("-o", "--output", type=str, default="nv-nc-ssl-output.txt", help="Output file. (Default: nv-nc-ssl-output.txt)")
    parser_ssl.add_argument("--message", type=str, default="info", help="Message to send for bannger grab.")
    parser_ssl.add_argument("--timeout", type=int, default=3, help="Timeout for socket connection (default: 3 seconds).")
    parser_ssl.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")

    args = parser.parse_args()
    argcomplete.autocomplete(parser)
    
    connect_and_get_response_multiple(get_hosts_from_file2(args.file), args.output if args.output else None, args.message, args.command if args.command else None, args.threads, args.timeout)