import imaplib
import ssl
from src.utilities.utilities import get_hosts_from_file

def tls_nv(hosts: list[str], errors, verbose):
    tls_enabled = []
    vuln = []
    tls_not_forced = []
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            mail = imaplib.IMAP4_SSL(ip, int(port), timeout=3)
            tls_enabled.append(host)

        except ssl.SSLError: vuln.append(host)
        except Exception:pass
    
    for host in tls_enabled:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            mail = imaplib.IMAP4(ip, int(port), 3)
            tls_not_forced.append(host)

        except Exception:pass
    
    if len(vuln) > 0:
        print("TLS NOT enabled on hosts:")
        for v in vuln:
            print(f"    {v}")
    
    if len(tls_not_forced) > 0:
        print("TLS is enabled but NOT forced on hosts:")
        for v in tls_not_forced:
            print(f"    {v}")
        

def tls_console(args):
    tls_nv(get_hosts_from_file(args.file), args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("imap")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_tls = subparsers.add_parser("tls", help="Checks idrac version")
    parser_tls.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_tls.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_tls.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_tls.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_tls.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_tls.set_defaults(func=tls_console)