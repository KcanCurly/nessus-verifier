import subprocess
import re
import ssl
import socket
import tomllib
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger

code = 1

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="TLS Misconfigurations (Version and Ciphers)")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.add_argument("--allow-white-ciphers", action="store_true", required=False, help="White named ciphers are fine from sslscan output")
    parser_task1.set_defaults(func=solve)
    

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan and not args.ignore_fail: 
        print("No id found in json file")
        return
    
    if args.config:
        with open(args.config, "rb") as f:
            data = tomllib.load(f)
            args.allow_white_ciphers = data[str(code)]["allow_white_ciphers"]
    
    hosts = scan.hosts
    
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    wrong_hosts = []
    expired_cert_hosts = []
    
    expired_cert_re = r"Not valid after:\s+\x1b\[31m(.*)\x1b\[0m"

    for host in hosts:
        try:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
                
            command = ["sslscan", "--no-fallback", "--no-renegotiation", "--no-group", "--no-heartbleed", "--iana-names", "--connect-timeout=3", host]
            result = subprocess.run(command, text=True, capture_output=True)
            if "Connection refused" in result.stderr or "enabled" not in result.stdout:
                continue

            expired_match = re.search(expired_cert_re, result.stdout)
            if expired_match:
                expired_cert_hosts.append(f"{host} - {expired_match.group(1)}")

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
                        if args.allow_white_ciphers: # We allow white ciphers
                            if "[" in cipher: # Non-white
                                if host not in weak_ciphers:
                                    weak_ciphers[host] = []
                                weak_ciphers[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                                bit = line.split()[2]
                                if "[33m]" in bit: # If it is a green or white output and bit is low
                                    if host not in weak_bits:
                                        weak_bits[host] = []
                                    weak_bits[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                        else:
                            if host not in weak_ciphers:
                                weak_ciphers[host] = []
                            weak_ciphers[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                        
                            bit = line.split()[2] # If it is a green output and bit is low
                            if "[33m]" in bit:
                                if host not in weak_bits:
                                    weak_bits[host] = []
                                weak_bits[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                        
            
            try:
                context = ssl.create_default_context()
                with socket.create_connection((ip, int(port)), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        pass
            except ssl.CertificateError as e:
                if "Hostname mismatch" in e.strerror:
                    wrong_hosts.append(host)
                else: continue
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(weak_ciphers) > 0:       
        print("Vulnerable TLS Ciphers on Hosts:")                
        for key, value in weak_ciphers.items():
            print(f"\t{key} - {", ".join(value)}")
    
    
    if len(weak_versions) > 0: 
        print()             
        print("Vulnerable TLS Versions on Hosts:")                
        for key, value in weak_versions.items():
            print(f"\t{key} - {", ".join(value)}")
            
    if len(weak_bits) > 0:
        print()
        print("Low Bits on Good Algorithms on Hosts:")
        for key, value in weak_versions.items():
            print(f"\t{key} - {", ".join(value)}")
    
    if len(wrong_hosts) > 0:
        print()
        print("Wrong hostnames on certficate on hosts:")
        for v in wrong_hosts:
            print(f"\t{v}")
            
    if len(expired_cert_hosts) > 0:
        print()
        print("Expired cert on hosts:")
        for v in expired_cert_hosts:
            print(f"\t{v}")
            
