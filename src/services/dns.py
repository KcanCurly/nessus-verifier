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
from src.utilities.utilities import get_hosts_from_file

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

def malicious_nv(hosts, domains, errors, verbose):
    vuln = []
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]  # Set the specific DNS server
        for malicious_domain in domains:
            try:
                answer = resolver.resolve(malicious_domain, "A")  # Query for A record
                print(answer)
    
            except Exception as e:
                if errors: print("Error:", e)

    if len(vuln) > 0:
        print(f"Host(s) that were able to resolve malicious domain '{malicious_domain}':")
        for v in vuln:
            print(f"    {v}")
    
def zone_transfer_nv(hosts, errors, verbose):
    vuln = []

    hosts = get_hosts_from_file(hosts)

    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]

        # If we don't have domain, we first need to get domain from ptr record
        if not domain:
            domain = find_domain_name(ip)
            if not domain:
                if errors: print("Couldn't found domain of the ip")
                continue

        try:
            command = ["dnsrecon", "-n", ip, "-a", "-d", domain]
            result = subprocess.run(command, capture_output=True, text=True)
            if "Zone Transfer was successful" in result.stdout:
                vuln.append(host)
                

        except Exception as e: 
            if errors: print("Error: ", e)
            
    if len(vuln) > 0:
        print("Zone Transfer Was Successful on Hosts:")
        for v in vuln:
            print(f"    {v}") 
    



def dnssec_nv(hosts, errors, verbose):
    vuln = []
    hosts = get_hosts_from_file(hosts)

    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        # If we don't have domain, we first need to get domain from ptr record
        if not domain:
            domain = find_domain_name(ip)
            if not domain:
                if errors: print("Couldn't found domain of the ip")
                continue

        try:
            command = ["dnsrecon", "-n", ip, "-d", domain]
            result = subprocess.run(command, capture_output=True, text=True)
            if "DNSSEC is not configured" in result.stdout:
                vuln.append(host)
                
        except Exception as e: 
            if errors: print("Error:", e)
        
    if len(vuln) > 0:
        print("DNSSEC is NOT configured on Hosts:")
        for v in vuln:
            print(f"    {v}")



def add_txt_record_nv(hosts, txt_record_name, txt_record_value, error, verbose):
    vuln = []
    hosts = get_hosts_from_file(hosts)

    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        
        # If we don't have domain, we first need to get domain from ptr record
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
            if error: print("Error: ", e)
            continue
        try:
            u = dns.update.Update(domain)
            u.add(txt_record_name, 3600, "TXT", txt_record_value)
            r = dns.query.tcp(u, ip, port=int(port))
            if dns.rcode.to_text(r.rcode()) == "NOERROR":
                vuln.append(host)
        except Exception as e:
            if error: print("Error: ", e)
        
    if len(vuln) > 0:
        print(f"'TXT' record named {txt_record_name} was added with value of '{txt_record_value}' on hosts:")
        for v in vuln:
            print(f"    {v}")


def cachepoison_nv(hosts, errors, verbose):
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
        except Exception as e:
            if errors:
                print("Error:", e)
        
    if len(vuln) > 0:
        print("Cache poison vulnerability detected on hosts:")
        for v in vuln:
            print(f"    {v}")

def any_check_nv(hosts, errors, verbose):
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
            
        except Exception as e: 
            if errors: print("ANY function error: ", e)    
                    
    if len(vuln) > 0:
        print("Hosts that answered to 'ANY' query:")
        for v in vuln:
            print(f"    {v}")

def recursion_nv(hosts, errors, verbose):
    vuln = []
    hosts = get_hosts_from_file(hosts)

    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]

        # If we don't have domain, we first need to get domain from ptr record
        if not domain:
            domain = find_domain_name(ip)
            if not domain: 
                if errors: print("Couldn't found domain of the ip")
                continue

        try:
            command = ["dnsrecon", "-n", ip, "-d", domain]
            result = subprocess.run(command, capture_output=True, text=True)
            if "Recursion enabled on" in result.stdout:
                vuln.append(host)
        except Exception as e:
            if errors: print("Error:", e)

    
    if len(vuln) > 0:
        print("Recursion is ENABLED on Hosts:")
        for v in vuln:
            print(f"    {v}")
            
def zone_transfer_console(args):
    zone_transfer_nv(args.file, args.errors, args.verbose)

def add_txt_record_console(args):
    add_txt_record_nv(args.file, args.name, args.value, args.errors, args.verbose)
    
def any_check_console(args):
    any_check_nv(args.file, args.errors, args.verbose)
    
def recursion_console(args):
    recursion_nv(args.file, args.errors, args.verbose)
    
def cachepoison_console(args):
    cachepoison_nv(args.file, args.errors, args.verbose)
    
def dnssec_console(args):
    dnssec_nv(args.file, args.errors, args.verbose)
    
def malicious_console(args):
    malicious_nv(args.file, args.domains, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser(help="DNS")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_addtxtrecord = subparsers.add_parser("txt", help="Checks if we can add a txt record")
    parser_addtxtrecord.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_addtxtrecord.add_argument("-n", "--name", type=str, default="NV-TEST", help="TXT Record name to be added (Default = NV-TEST).")
    parser_addtxtrecord.add_argument("-nv", "--value", type=str, default="NV-TEST", help="TXT Record name to be added (Default = Nessus-verifier-test).")
    parser_addtxtrecord.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_addtxtrecord.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_addtxtrecord.set_defaults(func=add_txt_record_console)
    
    parser_any = subparsers.add_parser("any", help="Checks ANY query")
    parser_any.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_any.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_any.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_any.set_defaults(func=any_check_console)
    
    parser_recursion = subparsers.add_parser("recursion", help="Checks if recursion is enabled")
    parser_recursion.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_recursion.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_recursion.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_recursion.set_defaults(func=recursion_console)
    
    parser_cacheposion = subparsers.add_parser("cacheposion", help="Checks if cache can be posioned")
    parser_cacheposion.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_cacheposion.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_cacheposion.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_cacheposion.set_defaults(func=cachepoison_console)
    
    parser_axfr = subparsers.add_parser("axfr", help="Checks if zone transfer is possible")
    parser_axfr.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_axfr.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_axfr.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_axfr.set_defaults(func=zone_transfer_console)
    
    parser_dnssec = subparsers.add_parser("dnssec", help="Checks if dnssec is enabled")
    parser_dnssec.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_dnssec.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_dnssec.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_dnssec.set_defaults(func=dnssec_console)
    
    parser_dnssec = subparsers.add_parser("malicious", help="Checks if malicious domain can be resolved")
    parser_dnssec.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_dnssec.add_argument("--domains", nargs="+", default=["accounts.googleaccesspoint.com", "86-adm.one", "pvkxculusei.xyz"], help="List of malicious domains seperated by space")
    parser_dnssec.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_dnssec.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_dnssec.set_defaults(func=malicious_console)
    