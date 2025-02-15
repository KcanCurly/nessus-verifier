import json
import subprocess
import re
import ssl
import socket
import requests
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
from rich.progress import TextColumn, Progress, BarColumn, TimeElapsedColumn
from rich.console import Console

def savetofile(path, message, mode = "a+"):
    with open(path, mode) as f:
        f.write(message)
        
def get_hosts_from_file(name, get_ports = True):
    try:
        with open(name, "r") as file:
            if get_ports: return list(set(line.strip() for line in file)) 
            else: return list(set(line.strip().split(":")[0] for line in file)) 
    except: return None
    
def confirm_prompt(prompt="Are you sure?", suppress = False):
    extra = " [y/N]: " if not suppress else ""
    while True:
        # Display the prompt and get user input
        response = input(prompt + extra).strip().lower()
        # Default to "n" if input is empty
        if response == "":
            return False
        # Handle valid inputs
        elif response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False
        else:
            print("Please respond with 'y/yes' or 'n/no'.")
            
            
def control_TLS(hosts, extra_command = "", white_results_are_good = False):
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    wrong_hosts = []
    for host in hosts:
        ip = host.split(":")[0]
        port  = host.split(":")[1]
            
        if extra_command:
            command = ["sslscan", extra_command, "-no-fallback", "--no-renegotiation", "--no-group", "--no-check-certificate", "--no-heartbleed", "--iana-names", "--connect-timeout=3", host]
        else: command = ["sslscan", "-no-fallback", "--no-renegotiation", "--no-group", "--no-check-certificate", "--no-heartbleed", "--iana-names", "--connect-timeout=3", host]
        result = subprocess.run(command, text=True, capture_output=True)
        if "Connection refused" in result.stderr or "enabled" not in result.stdout:
            continue
        
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
            if "Hostname mismatch" in e:
                wrong_hosts.append(host)
                    
      
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
            
            
def find_scan(file_path: str, target_id: int):
    with open(file_path, "r") as file:
        for line in file:
            g = GroupNessusScanOutput.from_json(json.loads(line))
            if g.id == target_id: return g
    return None  # If not found


def get_header_from_url(host, header, verbose=0) -> str | None:
    l= logger.setup_logging(verbose)
    try:
        resp = requests.get(f"https://{host}", allow_redirects=True, verify=False)
    except Exception:
        try:
            resp = requests.get(f"http://{host}", allow_redirects=True, verify=False)
        except Exception as e: 
            l.v3(f"Failed to get header {header} from {host}: {e}")
            return None
    except Exception as e: 
        l.v3(f"Failed to get header {header} from {host}: {e}")
        return None

    return resp.headers.get(header)


def get_classic_progress():
    return Progress(TimeElapsedColumn(), TextColumn("{task.fields[modulename]}"), BarColumn(), TextColumn("{task.completed}/{task.total}"))

def get_classic_console(force_terminal = False):
    return Console(height=10, force_terminal=force_terminal)