from ftplib import FTP
from ftplib import error_perm
from src.utilities.utilities import find_scan, add_default_parser_arguments, get_default_context_execution, add_default_solver_parser_arguments
from src.services.telnet import version_nv
from src.modules.nv_parse import GroupNessusScanOutput
import nmap
import requests

code = 7

def get_default_config():
    return """
["7"]
"""

class AMQP_Vuln_Data():
    def __init__(self, host: str, mechanisms: str):
        self.host = host
        self.mechanisms = mechanisms

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Cleartext Protocol Detected")
    add_default_solver_parser_arguments(parser_task1)
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve)
   
def solver_amqp_single(host, timeout, errors, verbose):
    try:
        nm = nmap.PortScanner()
        ip, port = host.split(":")
        nm.scan(ip, port, arguments=f'--script amqp-info')
        
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                tcp_info = nmap_host['tcp'][int(port)]
                if 'script' in tcp_info and 'amqp-info' in tcp_info['script']:
                    amqpinfo = tcp_info['script']['amqp-info']
                    for line in amqpinfo.splitlines():
                        if "mechanisms:" in line:
                            mech = line.split(":")[1].strip()
                            return AMQP_Vuln_Data(host, mech)
                                    
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
   
def solve_amqp(hosts, threads, timeout, errors, verbose):
    results: list[AMQP_Vuln_Data] = get_default_context_execution("Cleartext Protocol Detected - AMQP Cleartext Authentication", threads, hosts, (solver_amqp_single, timeout, errors, verbose))
    
    if results and len(results) > 0:
        print("AMQP Cleartext Authentication Detected:")
        for r in results:
            print(f"{r.host} - {r.mechanisms}")

def solve_basic_http_single(host, timeout, errors, verbose):
    try:
        response = requests.get(f"http://{host}", timeout=timeout)
        if response.status_code == 401 and "WWW-Authenticate" in response.headers:
            return host

    except Exception as e:
        if errors: print(f"Error for {host}: {e}")

def solve_basic_http(hosts, threads, timeout, errors, verbose):
    results = get_default_context_execution("Cleartext Protocol Detected - Basic Authentication Without HTTPS", threads, hosts, (solve_basic_http_single, timeout, errors, verbose))
    if results and len(results) > 0:
        print("Basic Authentication Without HTTPS Detected:")
        for value in results:
            print(f"{value}")

def solve_ftp_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        ftp = FTP()
        ftp.connect(ip, int(port), timeout=timeout)
        try:
            l = ftp.login()
            if "230" in l:
                return host

        except error_perm as e:
            if "530" in str(e):
                return host
        except Exception: pass
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")

def solve_ftp(hosts, threads, timeout, errors, verbose):
    results = get_default_context_execution("Cleartext Protocol Detected - Basic Authentication Without HTTPS", threads, hosts, (solve_ftp_single, timeout, errors, verbose))
    
    if results and len(results) > 0:
        print("FTP Supporting Cleartext Authentication Detected:")
        for value in results:
            print(f"{value}")

def solve(args, is_all = False):
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan: 
        if is_all: return
        if not args.ignore_fail: print("No id found in json file")
        return
    
    if args.file:
        hosts = scan.sub_hosts.get("Unencrypted Telnet Server", [])
        if hosts: version_nv(hosts, args.threads, args.timeout, args.errors, args.verbose)
        hosts = scan.sub_hosts.get("Basic Authentication Without HTTPS", [])
        if hosts: solve_basic_http(hosts, args.threads, args.timeout, args.errors, args.verbose)
        hosts = scan.sub_hosts.get("AMQP Cleartext Authentication", [])
        if hosts: solve_amqp(hosts, args.threads, args.timeout, args.errors, args.verbose)
        hosts = scan.sub_hosts.get("FTP Supports Cleartext Authentication", [])
        if hosts: solve_ftp(hosts, args.threads, args.timeout, args.errors, args.verbose)
    
    
    """
    # SMTP (TODO)
    try:
        hosts = scan.sub_hosts.get("54582")
        vuln = {}
        for host in hosts:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
            try:
                smtp = smtplib.SMTP(ip, int(port), timeout=5)
                smtp.ehlo()
                auths = smtp.esmtp_features.get("auth", "")
                print(f"Normal {auths}")
            except smtplib.SMTPServerDisconnected as t: # It could be that server requires TLS/SSL so we need to connect again with TLS
                try:
                    smtp = smtplib.SMTP_SSL(ip, int(port), timeout=5)
                    smtp.ehlo()
                    auths = smtp.esmtp_features.get("auth", "")
                    print(f"TLS {auths}")
                except Exception as e: print(e)
            except Exception as e: print(e)
    except Exception as e: print(e)
    """