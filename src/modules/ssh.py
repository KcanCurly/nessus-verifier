import subprocess
import argparse
import os
import re

protocol1 = []
versions = {}

cve_dict = {
    
}

vuln_kex = set()
vuln_mac = set()

vuln_hosts = set()


def check(directory_path, hosts = "hosts.txt"):
    
    ### ssh-audit to capture version
    
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()]  # Remove empty lines and whitespace
        
    # Define regular expression patterns
    protocol_pattern = r"Remote protocol version (\d+\.\d+)"
    software_pattern = r"remote software version ([\w_]+)"
    
    # Iterate over each host and run the command
    for host in hosts:
        ip = host
        port = 22
        if ":" in host:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
        command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", ip]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            
            # Find matches using the patterns
            protocol_match = re.search(protocol_pattern, result.stderr)
            software_match = re.search(software_pattern, result.stderr)
            
            if protocol_match:
                protocol_version = protocol_match.group(1)
                if protocol_version != "2.0":
                    protocol1.append(host)
            else: print(f"Could not found protocol version for {host}")
            
            if software_match:
                software_version = software_match.group(1)
                print(f"{host}: {software_version}")
                if software_version not in versions:
                    versions[software_version] = []
                versions[software_version].append(host)
            else: print(f"Could not found software version for {host}")
                

        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            continue
    
    if len(protocol1) > 0:
        print("Protocol Version 1:")
        for p in protocol1:
            print(f"\t{p}")
    
    for index, (key, value) in enumerate(versions.items()):
        print(key + ":")
        for v in value:
            print(f"\t{v}")
        
    
    for host in hosts:
        command = ["ssh-audit", host]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            lines = result.stdout.splitlines()
            is_vul = False
            for line in lines:
                if "0;31m(rec)" in line:
                    is_vul = True
                    
                    if "kex" in line:
                        vuln_kex.add(line.split()[1][1:])
                    elif "mac" in line:
                        vuln_mac.add(line.split()[1][1:])
        
            if is_vul:
                vuln_hosts.add(host)
        
        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            continue
    
    if len(vuln_kex) > 0:
        print("Vulnerable KEX algorithms found:")
        for k in vuln_kex:
            print(f"\t{k}")
            
    if len(vuln_mac) > 0:
        print("Vulnerable MAC algorithms found:")
        for k in vuln_mac:
            print(f"\t{k}")
            
    if len(vuln_hosts) > 0:
        print("Vulnerable hosts found:")
        for k in vuln_hosts:
            print(f"\t{k}")
    

def main():
    parser = argparse.ArgumentParser(description="SSH module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")