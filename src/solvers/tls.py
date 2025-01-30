import subprocess
import re
import ssl
import socket
import argparse
from src.utilities import get_hosts_from_file

def entry_solver(args):
    solve(args.file)

def entry_cmd():
    parser = argparse.ArgumentParser(description="TLS Misconfigurations (Version and Ciphers)")
    parser.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    
    args = parser.parse_args()
    
    entry_solver(args)

def solve(hosts, white_results_are_good = False):
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    wrong_hosts = []
    expired_cert_hosts = []
    
    expired_cert_re = r"Not valid after:\s+\^\[\[31m(.*)\^\[\[0m"
    
    hosts = get_hosts_from_file(hosts)
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
                expired_cert_hosts.append(f"{host} - {expired_match.group(0)}")

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
                    if "[32m" not in cipher: # If it is not green output
                        if host not in weak_ciphers:
                            weak_ciphers[host] = []
                        weak_ciphers[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                        continue
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
            
if __name__ == "__main__":
    entry_cmd()