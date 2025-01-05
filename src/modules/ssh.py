import subprocess
import argparse
import os

cve_dict = {
    
}

vuln_kex = set()
vuln_mac = set()

vuln_hosts = set()


def check(directory_path, hosts = "hosts.txt"):
    
    ### ssh-audit to capture version
    
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()]  # Remove empty lines and whitespace
        
    
    # Iterate over each host and run the command
    for host in hosts:
        command = ["ssh", "-vvv", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", host]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            first_line = result.stderr.splitlines()[0]
            first_word = first_line.split()[0]
        
            # Print the output of the command
            print(f"{host}: {first_word}")

        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            continue
            
    for host in hosts:
        command = ["ssh-audit", "--no-colors", host]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            lines = result.stdout.splitlines()
            is_vul = False
            for line in lines:
                if "(rec)" in line:
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