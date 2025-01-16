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
from dnslib import DNSRecord, DNSHeader, RR, A
import socket
from src.utilities import get_hosts_from_file

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
    vuln = []
    hosts = get_hosts_from_file(hosts)
    last_ip = ""
    last_port = ""
    last_domain = ""
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
            zone = dns.zone.from_xfr(dns.query.xfr(ip, domain, port=int(port), timeout=3))
            vuln.append(host)
            print(f"\nZone transfer on {host} was successful")
            last_port = port
            last_ip = ip
            last_domain = domain

        except Exception as e: print(e)
        
    if len(vuln) > 0:
        print("\nZone Transfer Was Successful on Hosts:")
        for v in vuln:
            print(f"\t{v}")
            
        print("Printing last one as an example")
        cmd = ["dig", "-p", last_port, f"@{last_ip}", last_domain]
        subprocess.run(cmd)
        

def update(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
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
            u.add("NV-TEST", 3600, "TXT", "Nessus verifier test")
            r = dns.query.tcp(u, ip, port=int(port))
            if dns.rcode.to_text(r.rcode()) == "NOERROR":
                vuln.append(host)
        except Exception as e: print("Error: ", e)
        
    if len(vuln) > 0:
        print("'TXT' record named 'NV-TEST' was added with value of 'Nessus verifier test' on hosts:")
        for v in vuln:
            print(v)

def any(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
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
            
                
    if len(vuln) > 0:
        print("There were more 'A' records than 'NS' Records on Hosts, check manually for 'ANY' query:")
        for v in vuln:
            print(f"\t{v}")

def cacheposion(directory_path, config, args, hosts):
    vuln = []
    hosts = get_hosts_from_file(hosts)
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]    
        fake_response = DNSRecord(
            DNSHeader(id=12345, qr=1, aa=1, ra=1),
            q=DNSRecord.question("lab.com"),
            a=RR("lab.com", rdata=A("1.111.111.111"), ttl=60)
        )

        # Send the spoofed response to the resolver
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fake_response_packet = fake_response.pack()
        sock.sendto(fake_response_packet, (ip, port))
        sock.close()
        print(f"Sent spoofed response for {"lab.com"} -> {ip}")

def check(directory_path, config, args, hosts):
    recursion(directory_path, config, args, hosts)
    axfr(directory_path, config, args, hosts)
    update(directory_path, config, args, hosts)
    any(directory_path, config, args, hosts)

def main():
    parser = argparse.ArgumentParser(description="Time Protocol module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("-n", "--number", default=0, type=int, required=False, help="Config file.")
    parser.add_argument("--domain", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args, args.filename or "hosts.txt")