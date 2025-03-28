import subprocess
import re
import ssl
import socket
import tomllib
from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments, get_default_context_execution
from src.modules.nv_parse import GroupNessusScanOutput

class TLS_Vuln_Data():
    def __init__(self, host: str, weak_versions: list[str], weak_ciphers: list[str], weak_bits: list[str], is_wrong_hostname: bool, is_cert_expired: str):
        self.host = host
        self.weak_versions = weak_versions
        self.weak_ciphers = weak_ciphers
        self.weak_bits = weak_bits
        self.is_wrong_hostname = is_wrong_hostname
        self.is_cert_expired = is_cert_expired

code = 1

def get_default_config():
    return """
["1"]
allow_white_ciphers = true
"""

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="TLS Misconfigurations")
    add_default_solver_parser_arguments(parser_task1)
    parser_task1.add_argument("--allow-white-ciphers", action="store_true", required=False, help="White named ciphers are fine from sslscan output")
    add_default_parser_arguments(parser_task1, False)
    parser_task1.set_defaults(func=solve)
    

def tls_single(host, allow_white_ciphers, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        
        expired_cert_re = r"Not valid after:\s+\x1b\[31m(.*)\x1b\[0m"
        
        weak_versions = {}
        weak_ciphers = {}
        weak_bits = {}
        is_wrong_host = False
        is_cert_expired = ""
        
        command = ["sslscan", "--no-fallback", "--no-renegotiation", "--no-group", "--no-heartbleed", "--iana-names", f"--connect-timeout={timeout}", host]
        result = subprocess.run(command, text=True, capture_output=True)
        
        # Fail conditions
        if "Connection refused" in result.stderr:
            return TLS_Vuln_Data(host, weak_versions, weak_ciphers, weak_bits, is_wrong_host, is_cert_expired)
        if "enabled" not in result.stdout:
            return TLS_Vuln_Data(host, weak_versions, weak_ciphers, weak_bits, is_wrong_host, is_cert_expired)

        expired_match = re.search(expired_cert_re, result.stdout)
        if expired_match:
            is_cert_expired = expired_match.group(1)

        lines = result.stdout.splitlines()
        protocol_line = False
        cipher_line = False
        for line in lines:
            if "SSL/TLS Protocols" in line:
                protocol_line = True
                continue
            if "Supported Server Cipher(s)" in line:
                protocol_line = False
                cipher_line = True
                continue
            if "Server Key Exchange Group(s)" in line:
                cipher_line = False
                continue
            if protocol_line:
                if "enabled" in line:
                    if "SSLv2" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("SSLv2")
                    elif "SSLv3" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("SSLv3")
                    elif "TLSv1.0" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("TLSv1.0")
                    elif "TLSv1.1" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("TLSv1.1")
            
            if cipher_line and line:
                cipher = line.split()[4]
                if "[32m" not in cipher: # Non-green
                    if allow_white_ciphers: # We allow white ciphers
                        if "[" in cipher: # Non-white
                            if host not in weak_ciphers:
                                weak_ciphers[host] = set()
                            weak_ciphers[host].add(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                            bit = line.split()[2]
                            if "[33m]" in bit: # If it is a green or white output and bit is low
                                if host not in weak_bits:
                                    weak_bits[host] = set()
                                weak_bits[host].add(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                    else:
                        if host not in weak_ciphers:
                            weak_ciphers[host] = set()
                        weak_ciphers[host].add(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                    
                        bit = line.split()[2] # If it is a green output and bit is low
                        if "[33m]" in bit:
                            if host not in weak_bits:
                                weak_bits[host] = set()
                            weak_bits[host].add(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
    except Exception as e: pass
                   
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                pass
    except ssl.CertificateError as e:
        if "Hostname mismatch" in e.strerror:
            is_wrong_host = True
    except Exception: pass
    
    return TLS_Vuln_Data(host, weak_versions, weak_ciphers, weak_bits, is_wrong_host, is_cert_expired)

def tls_nv(hosts, allow_white_ciphers, threads, timeout, errors, verbose):
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    wrong_hosts = []
    expired_cert_hosts = []
    results: list[TLS_Vuln_Data] = get_default_context_execution("TLS Misconfigurations", threads, hosts, (tls_single, allow_white_ciphers, timeout, errors, verbose))

    for r in results:
        if not r: continue
        weak_versions.update(r.weak_versions)
        weak_ciphers.update(r.weak_ciphers)
        weak_bits.update(r.weak_bits)
        if r.is_wrong_hostname:
            wrong_hosts.append(r.host)
        if r.is_cert_expired:
            expired_cert_hosts.append(f"{r.host} - {r.is_cert_expired}")
    
    if len(weak_ciphers) > 0:       
        print("Vulnerable TLS Ciphers on Hosts:")                
        for key, value in weak_ciphers.items():
            print(f"    {key} - {", ".join(value)}")
    
    
    if len(weak_versions) > 0: 
        print()             
        print("Vulnerable TLS Versions on Hosts:")                
        for key, value in weak_versions.items():
            print(f"    {key} - {", ".join(value)}")
            
    if len(weak_bits) > 0:
        print()
        print("Low Bits on Good Algorithms on Hosts:")
        for key, value in weak_versions.items():
            print(f"    {key} - {", ".join(value)}")
    
    if len(wrong_hosts) > 0:
        print()
        print("Wrong hostnames on certficate on hosts:")
        for v in wrong_hosts:
            print(f"    {v}")
            
    if len(expired_cert_hosts) > 0:
        print()
        print("Expired cert on hosts:")
        for v in expired_cert_hosts:
            print(f"    {v}")
    

def solve(args, is_all = False):
    hosts = []
    if args.file:
        scan: GroupNessusScanOutput = find_scan(args.file, code)
        if not scan: 
            if is_all: return
            if not args.ignore_fail: print("No id found in json file")
            return
        hosts = scan.hosts
    elif args.list_file:
        with open(args.list_file, 'r') as f:
            hosts = [line.strip() for line in f]
    
    if is_all:
        with open(args.config, "rb") as f:
            data = tomllib.load(f)
            args.allow_white_ciphers = data[str(code)]["allow_white_ciphers"]
        
    tls_nv(hosts, args.allow_white_ciphers, args.threads, args.timeout, args.errors, args.verbose)
