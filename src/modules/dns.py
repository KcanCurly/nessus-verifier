import argparse
import os
from pathlib import Path
import dns.query
import dns.message
import configparser
from src.utilities import get_hosts_from_file

def recursion(directory_path, config, verbose, hosts = "hosts.txt"):
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
            response = dns.query.udp(query, ip, port=port ,timeout=5)
            
            # Check if the Recursion Available (RA) flag is set in the response
            if response.flags & dns.flags.RA:
                vuln.append(host)

        except Exception as e:
            pass
    
    if len(vuln) > 0:
        print("Recursion is SUPPORTED on Hosts:")
        for v in vuln:
            print(v)


def check(directory_path, config, verbose, hosts = "hosts.txt"):
    recursion(directory_path, config, verbose, hosts = "hosts.txt")

def main():
    parser = argparse.ArgumentParser(description="Time Protocol module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args.verbose, args.filename or "hosts.txt")