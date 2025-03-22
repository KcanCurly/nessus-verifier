import json
import subprocess
import re
import ssl
import socket
import requests
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
from rich.progress import TextColumn, Progress, BarColumn, TimeElapsedColumn, SpinnerColumn
from rich.console import Console
from rich.table import Column
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.live import Live
import os

def savetofile(path, message, mode = "a+"):
    with open(path, mode) as f:
        f.write(message)
        
def get_hosts_from_file(name, get_ports = True):
    if os.path.isfile(name):
        with open(name, "r") as file:
            if get_ports: return list(set(line.strip() for line in file)) 
            else: return list(set(line.strip().split(":")[0] for line in file)) 
    else: return list(set(name.split())) 
    
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
            if g.id == target_id and not len(g.hosts) == 0: return g
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

    return resp.headers.get(header, "None")

def get_classic_single_progress():
    text_column1 = TextColumn("{task.fields[host]}", table_column=Column(ratio=1), style= "bold")
    text_column2 = TextColumn("{task.fields[status]}", table_column=Column(ratio=1), style= "dim")
    
    return Progress(text_column1, SpinnerColumn(), text_column2, refresh_per_second= 1)

def get_classic_overall_progress():
    return Progress(TimeElapsedColumn(), TextColumn("{task.fields[modulename]}"), BarColumn(), TextColumn("{task.completed}/{task.total}"), refresh_per_second=1)

def get_classic_console(force_terminal = False):
    return Console(force_terminal=force_terminal)

def get_default_context_execution(module_name, threads, hosts, args):
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename=module_name)
    
    futures = []
    results = []
    """A reusable context manager to handle file, Live display, and thread execution."""
    with Live(overall_progress) as live, ThreadPoolExecutor(threads) as executor:
        overall_progress.update(overall_task_id, total=len(hosts), completed=0)
        overall_progress.start_task(overall_task_id)
        for host in hosts:
            modified_args = (args[0], host) + args[1:]
            future = executor.submit(*modified_args)
            futures.append(future)
        for a in as_completed(futures):
            overall_progress.update(overall_task_id, advance=1)
            if a.result(): results.append(a.result())
            
    return results

def add_default_parser_arguments(parser, add_target_argument = True):
    if add_target_argument: parser.add_argument("target", type=str, help="File name or targets seperated by space")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    parser.add_argument("--timeout", type=int, default=5, help="Amount of timeout (Default = 5).")
    parser.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    
def get_url_response(url, timeout=5):
    try:
        resp = requests.get(f"http://{url}", allow_redirects=True, verify=False, timeout=timeout)
        if "You're speaking plain HTTP to an SSL-enabled server port" in resp.text: return requests.get(f"https://{url}", allow_redirects=True, verify=False, timeout=timeout)
        return resp
    except:
        try:
            return requests.get(f"https://{url}", allow_redirects=True, verify=False, timeout=timeout)
        except Exception as e:
            return None