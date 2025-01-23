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

def recursion(directory_path, config, args, hosts = "hosts.txt"):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    
    # Create a DNS query message
    query = dns.message.make_query('google.com.', dns.rdatatype.A)
    
    # Send the query with recursion desired
    query.flags |= dns.flags.RD  # Set the RD (Recursion Desired) flag
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]

        try:
            response = dns.query.udp(query, ip, port=int(port), timeout=3)
            
            # Check if the Recursion Available (RA) flag is set in the response
            if response.flags & dns.flags.RA:
                vuln.append(host)

        except Exception as e:
            pass
    
    if len(vuln) > 0:
        print("Recursion is SUPPORTED on Hosts:")
        for v in vuln:
            print(f"\t{v}")

def axfr(directory_path, config, args, hosts):
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
        
    if len(axfr_vuln) > 0:
        print("\nZone Transfer Was Successful on Hosts:")
        for v in axfr_vuln:
            print(f"\t{v}")
            
        print("Printing last one as an example")
        print(f"Running command: dnsrecon -n {last_ip} -t axfr -d {last_domain}")
        command = ["dnsrecon", "-n", last_ip, "-t", "axfr", "-d", last_domain]
        subprocess.run(command)
        
    if len(dnssec_vuln) > 0:
        print("\nDNSSEC is NOT configured on Hosts:")
        for v in dnssec_vuln:
            print(f"\t{v}")
    
    if len(dnssec_vuln) > 0:
        print("\nRecursion is ENABLED on Hosts:")
        for v in dnssec_vuln:
            print(f"\t{v}")

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
            print(v)

def any(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            reverse_name = dns.reversename.from_address(ip)
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.port = int(port)  # Specify the port for the resolver
            
            answers = resolver.resolve(reverse_name, 'PTR')
                    
            for rdata in answers:
                domain = rdata.to_text()
                parts = domain.split('.')
                domain = '.'.join(parts[-3:])
            
            answer = resolver.resolve(domain, "ANY")
            
            # Normally we should get 
            a_records = []
            ns_records = []
            for rdata in answer:
                if rdata.rdtype == dns.rdatatype.A:
                    a_records.append(rdata)
                elif rdata.rdtype == dns.rdatatype.NS:
                    ns_records.append(rdata)
                    
            if len(a_records) > len(ns_records):
                vuln.append(host)
        except Exception as e: print("ANY function error: ", e)    
                
    if len(vuln) > 0:
        print("There were more 'A' records than 'NS' Records on Hosts, check manually for 'ANY' query:")
        for v in vuln:
            print(f"\t{v}")
        

def check(directory_path, config, args, hosts):
    # recursion(directory_path, config, args, hosts)
    axfr(directory_path, config, args, hosts)
    update(directory_path, config, args, hosts)
    # any(directory_path, config, args, hosts)

def main():
    parser = argparse.ArgumentParser(description="Time Protocol module of nessus-verifier.")
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