from ftplib import FTP
from ftplib import error_perm
import tomllib
from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
import nmap
import requests

code = 7

def get_default_config():
    return """
["7"]
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Cleartext Protocol Detected")
    group = parser_task1.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    parser_task1.set_defaults(func=solve)
   
def solve_amqp(scan: GroupNessusScanOutput):
    try:
        hosts = scan.sub_hosts.get("87733")
        if not hosts: return
        vuln = {}    
        nm = nmap.PortScanner()
        for host in hosts:
            try:
                ip = host.split(":")[0]
                port = host.split(":")[1]
                nm.scan(ip, port, arguments=f'--script amqp-info')
                
                if ip in nm.all_hosts():
                    nmap_host = nm[ip]
                    if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                        tcp_info = nmap_host['tcp'][int(port)]
                        if 'script' in tcp_info and 'amqp-info' in tcp_info['script']:

                            amqpinfo = tcp_info['script']['amqp-info']

                            mech = None

                            for line in amqpinfo.splitlines():
                                if "mechanisms:" in line:
                                    mech = line.split(":")[1].strip()
                            if mech:
                                vuln[host] = mech

            except Exception as e: pass #print(e)
        
        if len(vuln) > 0:
            print("AMQP Plain Authentication Mechanism Detected:")
            for key, value in vuln.items():
                print(f"{key}: {value}")
    except: pass

def solve_telnet(hosts):
    try:
        vuln = []   
        nm = nmap.PortScanner()
        for host in hosts:
            try:
                ip, port = host.split(":")
                nm.scan(ip, port, arguments=f'-sV')
                
                if ip in nm.all_hosts():
                    nmap_host = nm[ip]
                    if nmap_host['tcp'][int(port)]['name'].lower() == 'telnet':
                        vuln.append(f"{host} - {nmap_host['tcp'][int(port)].get("version", "Service not found")}")
                        
            except: pass
        
        if len(vuln) > 0:
            print("Unencrypted Telnet Detected:")
            for value in vuln:
                print(f"{value}")
    except: pass

def solve_basic_http(scan: GroupNessusScanOutput):
    try:
        hosts = scan.sub_hosts.get("98615")
        if not hosts: return
        vuln = []
        for host in hosts:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
            try:
                response = requests.get(f"http://{host}", timeout=5)
                if response.status_code == 401 and "WWW-Authenticate" in response.headers:
                    vuln.append(host)

            except: pass
            
        if len(vuln) > 0:
            print("Basic Authentication Without HTTPS Detected:")
            for value in vuln:
                print(f"{value}")
    except: pass

def solve_ftp(scan: GroupNessusScanOutput):
    try:
        hosts = scan.sub_hosts.get("34324")
        if not hosts: return
        vuln = []
        for host in hosts:
            ip = host.split(":")[0]
            port  = int(host.split(":")[1])

            ftp = FTP()
            ftp.connect(ip, port)
            try:
                l = ftp.login()
                if "230" in l:
                    vuln.append(host)

            except error_perm as e:
                if "530" in str(e):
                    vuln.append(host)
            except Exception: pass
                
        if len(vuln) > 0:
            print("FTP Supports Cleartext Authentication:")
            for value in vuln:
                print(f"{value}")
    except: pass

def solve(args, is_all = False):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan: 
        if is_all: return
        if not args.ignore_fail: print("No id found in json file")
        return
    
    if args.file:
        hosts = scan.sub_hosts.get("Unencrypted Telnet Server", [])

    solve_telnet(hosts)

    
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