import socket
from src.utilities.utilities import get_hosts_from_file

def monlist_nv(hosts, timeout, errors, verbose):
    vuln = []
    
    request = b'\x17\x00\x03\x2a' + b'\x00' * 40
    for host in hosts:
        try:
            ip, port = host.split(":")
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(request, (ip, int(port)))
                data, addr = s.recvfrom(1024)
                print(f"Received {len(data)} bytes from {addr}")
                print(data)
                vuln.append(host)
            
        except Exception as e: 
            if errors: print(e)
    
    if len(vuln) > 0:
        print("NTP service monlist enabled on hosts:")
        for v in vuln:
            print(f"    {v}")
        
def monlist_console(args):
    monlist_nv(get_hosts_from_file(args.file), args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ntp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("monlist", help="Checks if monlist command is enabled")
    parser_version.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_version.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_version.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_version.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_version.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_version.set_defaults(func=monlist_console)