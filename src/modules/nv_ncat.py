from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2, Version_Vuln_Host_Data
import argparse, argcomplete
import socket
import ssl
import subprocess

@error_handler(["host"])
def normal_connect_and_get_response_single(host, **kwargs):
    timeout = kwargs.get("timeout", 5)  # Default timeout is 5 seconds
    message = kwargs.get("message", "info")
    command = "nc" if not kwargs.get("use_nc", False) else "ncat"

    if command == "nc":
        real_command = ["timeout", f"{timeout}s", "nc", host.ip, host.port]
    elif command == "ncat":
        real_command = ["ncat", host.ip, host.port, "--recv-only", "--wait", str(timeout)]


    try:
        result = subprocess.run(
            real_command,
            timeout=timeout+1,
            capture_output=True,
            text=True
        )
        if result.stdout:
            return Version_Vuln_Host_Data(host, result.stdout.strip())
    except subprocess.TimeoutExpired as e:
        if result.stdout:
            return Version_Vuln_Host_Data(host, result.stdout.strip())
    except Exception as e:
        print(f"Error connecting to {host.ip}:{host.port} - {e}")
        
@error_handler(["host"])
def ssl_connect_and_get_response_single(host, **kwargs):
    timeout = kwargs.get("timeout", 5)
    message = kwargs.get("message", "info")
    command = "ncat" if not kwargs.get("use_openssl", False) else "nc"

    if command == "nc":
        real_command = ["timeout", f"{timeout}s", "nc", host.ip, host.port]
    elif command == "ncat":
        real_command = ["ncat", host.ip, host.port, "--recv-only", "--wait", str(timeout)]


    try:
        result = subprocess.run(
            real_command,
            timeout=timeout+1,
            capture_output=True,
            text=True
        )
        if result.stdout:
            return Version_Vuln_Host_Data(host, result.stdout.strip())
    except subprocess.TimeoutExpired as e:
        if result.stdout:
            return Version_Vuln_Host_Data(host, result.stdout.strip())

    
def ssl_connect_and_get_response(hosts, output, message, threads, timeout):
    results: list[Version_Vuln_Host_Data] = get_default_context_execution2("banner grab", threads, hosts, ssl_connect_and_get_response_single, message=message, timeout=timeout)
    
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

def normal_connect_and_get_response(hosts, output, message, threads, timeout):
    results: list[Version_Vuln_Host_Data] = get_default_context_execution2("banner grab", threads, hosts, normal_connect_and_get_response_single, message=message, timeout=timeout)
    
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
    parser_normal.add_argument("-e", "--errors", type=int, choices=[1, 2], default = 0, help="1 - Print Errors\n2 - Print errors and prints stacktrace")
    parser_normal.add_argument("-v", "--verbose", action="store_true", help="Print Verbose")
    parser_normal.add_argument("--use-nc", action="store_true", help="Use nc instead of ncat.")

    parser_ssl = subparsers.add_parser("ssl", help="Runs with ssl")
    parser_ssl.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser_ssl.add_argument("-o", "--output", type=str, default="nv-nc-ssl-output.txt", help="Output file. (Default: nv-nc-ssl-output.txt)")
    parser_ssl.add_argument("--message", type=str, default="info", help="Message to send for bannger grab.")
    parser_ssl.add_argument("--timeout", type=int, default=3, help="Timeout for socket connection (default: 3 seconds).")
    parser_ssl.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    parser_ssl.add_argument("-e", "--errors", type=int, choices=[1, 2], default = 0, help="1 - Print Errors\n2 - Print errors and prints stacktrace")
    parser_ssl.add_argument("-v", "--verbose", action="store_true", help="Print Verbose")
    parser_ssl.add_argument("--use-openssl", action="store_true", help="Use openssl connect instead of ncat.")

    args = parser.parse_args()
    argcomplete.autocomplete(parser)

    if args.command == "normal":
        normal_connect_and_get_response(get_hosts_from_file2(args.file), args.output if args.output else None, args.message, args.threads, args.timeout)
    elif args.command == "ssl":
        ssl_connect_and_get_response(get_hosts_from_file2(args.file), args.output if args.output else None, args.message, args.threads, args.timeout)