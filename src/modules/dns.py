import argparse
import os
from pathlib import Path
import dns.query
import dns.message
import configparser
import subprocess
import dns.rcode
import dns.resolver
import dns.reversename
import dns.update
import dns.zone
import re
from src.utilities import get_hosts_from_file

def find_domain_name(ip):
    domain_name_pattern = r"PTR\s(.*?)\s+"
    try:
        command = ["dnsrecon", "-n", ip, "-t", "rvl", "-r", f"{ip}/31"]
        result = subprocess.run(command, capture_output=True, text=True)
        domain_match = re.search(domain_name_pattern, result.stdout)
        if domain_match and "in-addr.arpa" not in domain_match.group(1):
            domain = domain_match.group(1)
            domain = ".".join(domain.split(".")[1:])
            return domain
        else: return None # Couldn't find domain name
        
    except Exception as e:
        print("dnsrecon find domain name failed: ", e)
        return None


def tls(directory_path, config, args, hosts):
    no_tls = []
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        ip = host.split(":")[0]
        port  = 853

        command = ["sslscan", "-no-fallback", "--no-renegotiation", "--no-group", "--no-check-certificate", "--no-heartbleed", "--iana-names", "--connect-timeout=2", f"{host}:{port}"]
        result = subprocess.run(command, text=True, capture_output=True)
        if "Connection refused" in result.stderr or "enabled" not in result.stdout:
            no_tls.append(host)
            continue
        
        host = ip + ":" + port
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
                    
      
    if len(no_tls) > 0:
        print("No DNS over TLS supported on Hosts:")
        for v in no_tls:
            print(f"\t{v}")
    
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

def malware(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    malicious_domain = "accounts.googleaccesspoint.com"
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        
        command = ["dig", f"@{ip}", "example.com"]
        result = subprocess.run(command, text=True, capture_output=True)
        if "recursion requested but not available" not in result.stdout:
            # We were able to resolve example.com, now we try known malware website
            command = ["dig", f"@{ip}", malicious_domain]
            result = subprocess.run(command, text=True, capture_output=True)
            if "recursion requested but not available" in result.stdout or \
                "status: NXDOMAIN" in result.stdout or \
                    "ANSWER: 0" in result.stdout:
                        continue
            else: vuln.append(host)
            
    if len(vuln) > 0:
        print(f"Host(s) that were able to resolve malicious domain '{malicious_domain}':")
        for v in vuln:
            print(f"\t{v}")
    
    

def dnsrecon(directory_path, config, args, hosts):
    axfr_vuln = []
    dnssec_vuln = []
    recursion_vuln = []
    hosts = get_hosts_from_file(hosts)
    last_ip = ""
    last_port = ""
    last_domain = ""
    domain_name_pattern = r"PTR\s(.*?)\s+"
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        domain = args.domain
        # If we don't have domain, we first need to get domain from ptr record
        if not domain:
            domain = find_domain_name(ip)
            if not domain: break

        try:
            command = ["dnsrecon", "-n", ip, "-a", "-d", domain]
            result = subprocess.run(command, capture_output=True, text=True)
            if "Zone Transfer was successful" in result.stdout:
                last_ip = ip
                last_domain = domain
                axfr_vuln.append(host)
                
            if "DNSSEC is not configured" in result.stdout:
                dnssec_vuln.append(host)
                
            if "Recursion enabled on" in result.stdout:
                recursion_vuln.append(host)
        except Exception as e: print("dnsrecond axfr failed: ", e)
        
    """
    if len(dnssec_vuln) > 0:
        print("\nDNSSEC is NOT configured on Hosts:")
        for v in dnssec_vuln:
            print(f"\t{v}")
    """
    
    if len(dnssec_vuln) > 0:
        print("\nRecursion is ENABLED on Hosts:")
        for v in dnssec_vuln:
            print(f"\t{v}")
            
    if len(axfr_vuln) > 0:
        print("\nZone Transfer Was Successful on Hosts:")
        for v in axfr_vuln:
            print(f"\t{v}")
            
        print("Printing last one as an example")
        print(f"Running command: dnsrecon -n {last_ip} -t axfr -d {last_domain}")
        command = ["dnsrecon", "-n", last_ip, "-t", "axfr", "-d", last_domain]
        subprocess.run(command)

def update(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    txt_record_name = "NV-TEST"
    txt_record_value = "Nessus-verifier-test"
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        
        # If we don't have domain, we first need to get domain from ptr record
        if not args.domain:
            try:
                reverse_name = dns.reversename.from_address(ip)
                
                # Perform the PTR query
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [ip]
                resolver.port = int(port)  # Specify the port for the resolver
                
                answers = resolver.resolve(reverse_name, 'PTR')
                
                for rdata in answers:
                    domain = rdata.to_text()
                    parts = domain.split('.')
                    domain = '.'.join(parts[-3:])
            except Exception as e:
                print("Error: ", e)
                continue
        try:
            u = dns.update.Update(domain)
            u.add(txt_record_name, 3600, "TXT", txt_record_value)
            r = dns.query.tcp(u, ip, port=int(port))
            if dns.rcode.to_text(r.rcode()) == "NOERROR":
                vuln.append(host)
        except Exception as e: pass #print("Error: ", e)
        
    if len(vuln) > 0:
        print(f"'TXT' record named {txt_record_name} was added with value of '{txt_record_value}' on hosts:")
        for v in vuln:
            print(f"\t{v}")


def cachepoison(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            command = ["dig", f"@{ip}", "example.com"]
            result = subprocess.run(command, text=True, capture_output=True)
            answer = re.search("ANSWER: (.*), AUTHORITY", result.stdout)
            if answer:
                answer = int(answer.group(1))
                if answer > 0:
                    command = ["dig", f"@{ip}", "example.com", "+norecurse"]
                    result = subprocess.run(command, text=True, capture_output=True)
                    answer2 = re.search("ANSWER: (.*), AUTHORITY", result.stdout)
                    if answer2:
                        answer2 = int(answer2.group(1))
                        if answer == answer2:
                            vuln.append(host)   
        except: pass
        
    if len(vuln) > 0:
        print("Cache poison vulnerability detected on hosts:")
        for v in vuln:
            print(f"\t{v}")

def any(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            command = ["dig", "any", f"@{ip}", "example.com"]
            result = subprocess.run(command, text=True, capture_output=True)
            answer = re.search("ANSWER: (.*), AUTHORITY", result.stdout)
            if answer:
                answer = int(answer.group(1))
                if answer > 0:
                    vuln.append(host)
            
        except Exception as e: print("ANY function error: ", e)    
    
                
    if len(vuln) > 0:
        print("Hosts that answered to 'ANY' query:")
        for v in vuln:
            print(f"\t{v}")
        

def check(directory_path, config, args, hosts):
    dnsrecon(directory_path, config, args, hosts)
    update(directory_path, config, args, hosts)
    tls(directory_path, config, args, hosts)
    malware(directory_path, config, args, hosts)
    cachepoison(directory_path, config, args, hosts)
    any(directory_path, config, args, hosts)

def main():
    parser = argparse.ArgumentParser(description="DNS module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("--domain", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args, args.filename or "hosts.txt")