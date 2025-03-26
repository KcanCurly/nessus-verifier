import json
import os
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Any, List

import requests
from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Column

from src.modules.nv_parse import GroupNessusScanOutput


@dataclass
class Credential:
    username: str
    password: str

@dataclass
class Host:
    ip: str
    port: str
    
class Version_Vuln_Data():
    def __init__(self, host: str, version: str) -> None:
        self.host: str = host
        self.version: str = version
        
class Version_List_Vuln_Data():
    def __init__(self, host: str, values: list[Any]) -> None:
        self.host: str = host
        self.values: list[Any] = values

def savetofile(path: str, message: str, mode: str = "a+") -> None:
    with open(path, mode) as f:
        f.write(message)
        
def get_hosts_from_file(name: str, get_ports: bool = True) -> list[Host]:
    """
    Reads a list of hosts from a file and returns a list of Host instances.

    Each line in the file should contain an IP address and a port, separated by ":".

    Args:
        filename (str): The path to the file containing nessus scan information.
        id (int): Value of id of target.
    Returns:
        GroupNessusScanOutput: Nessus scan output.
    Raises:
            FileNotFoundError: If the specified file does not exist.
            IndexError: If ID does not exist.
    """
    if os.path.isfile(name):
        s: set[Host] = set()
        with open(name, "r") as file:
            for line in file:
                parts: list[str] = line.strip().split()
                ip: str = parts[0]
                port: str = parts[1] if get_ports else ""
                s.add(Host(ip, port))
        return list(s)
    else:
        raise FileNotFoundError(f"No file found named: {name}")
    
def confirm_prompt(prompt: str = "Are you sure?", suppress: bool = False) -> bool:
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
            
"""        
def control_TLS(hosts: list[Host], extra_command: str = "", white_results_are_good: bool = False) 
-> None:
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    wrong_hosts = []
    for host in hosts:
        ip = host.split(":")[0]
        port  = host.split(":")[1]
            
        if extra_command:
            command = ["sslscan", extra_command, "-no-fallback", "--no-renegotiation", "--no-group",
            "--no-check-certificate", "--no-heartbleed", "--iana-names", "--connect-timeout=3", host]
        else: command = ["sslscan", "-no-fallback", "--no-renegotiation", "--no-group", 
        "--no-check-certificate", "--no-heartbleed", "--iana-names", "--connect-timeout=3", host]
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
 """
            
def find_scan(filename: str, id: int) -> GroupNessusScanOutput:
    """
    Reads nessus file and returns GroupNessusScanOutput.

    Args:
        filename (str): The path to the file containing nessus scan information.
        id (int): Value of id of target.
    Returns:
        GroupNessusScanOutput: Nessus scan output.
    Raises:
            FileNotFoundError: If the specified file does not exist.
            IndexError: If ID does not exist.
    """
    if os.path.isfile(filename):
        with open(filename, "r") as file:
            for line in file:
                g: GroupNessusScanOutput = GroupNessusScanOutput.from_json(json.loads(line)) # type: ignore
                if g.id == id and g.hosts:  # type: ignore
                    return g # type: ignore
            raise IndexError(f"ID value of {id} was not found")
    else:
        raise FileNotFoundError(f"No file found named: {filename}")
        


def get_header_from_url(host: Host, header: str, timeout: int = 5, errors: bool = False, 
                        verbose: bool = False) -> str | None:
    """
    Returns the wanted header value from given url.

    Args:
        host (Host): Host information.
        header (str): Wanted header name.
        timeout (int): Timeout to reach the url
        errors (bool): Print errors
        verbose (bool): Print verbose
    Returns:
        str: Header value. returns "None" if not found
    Raises:
            FileNotFoundError: If the specified file does not exist.
            IndexError: If ID does not exist.
    """
    resp = get_url_response(host, timeout=timeout)
    if not resp:
        if errors:
            print(f"get_header_from_url failed for {host} because response was None")
        return None
    header = resp.headers.get(header, "None")
    return header

def get_classic_single_progress() -> Progress:
    text_column1 = TextColumn("{task.fields[host]}", table_column=Column(ratio=1), style= "bold")
    text_column2 = TextColumn("{task.fields[status]}", table_column=Column(ratio=1), style= "dim")
    
    return Progress(text_column1, SpinnerColumn(), text_column2, refresh_per_second= 1)

def get_classic_overall_progress() -> Progress:
    return Progress(TimeElapsedColumn(), TextColumn("{task.fields[modulename]}"), BarColumn(), 
                    TextColumn("{task.completed}/{task.total}"), refresh_per_second=1)

def get_classic_console(force_terminal: bool = False) -> Console:
    return Console(force_terminal=force_terminal)

def get_default_context_execution(module_name: str, threads: int, hosts: list[Host], 
                                  args: tuple[Any, ...]) -> list[Any]:
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename=module_name)
    
    futures: list[Any] = []
    results: list[Any] = []
    """A reusable context manager to handle file, Live display, and thread execution."""
    with Live(overall_progress) as live, ThreadPoolExecutor(threads) as executor:
        overall_progress.update(overall_task_id, total=len(hosts), completed=0)
        overall_progress.start_task(overall_task_id)
        for host in hosts:
            modified_args = (args[0], host) + args[1:]
            future = executor.submit(*modified_args)  # type: ignore
            futures.append(future)  # type: ignore
        for a in as_completed(futures):  # type: ignore
            overall_progress.update(overall_task_id, advance=1)
            if a.result(): 
                results.append(a.result())
            
    return results

def add_default_parser_arguments(parser, add_target_argument = True):
    if add_target_argument: parser.add_argument("target", type=str, help="File name or targets seperated by space")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    parser.add_argument("--timeout", type=int, default=5, help="Amount of timeout (Default = 5).")
    parser.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")

def add_default_solver_parser_arguments(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="JSON file")
    group.add_argument("-lf", "--list-file", type=str, help="List file")
    
def get_url_response(url, timeout=5, redirect = True):
    try:
        resp = requests.get(f"http://{url}", allow_redirects=redirect, verify=False, timeout=timeout)
        if "You're speaking plain HTTP to an SSL-enabled server port" in resp.text: return requests.get(f"https://{url}", allow_redirects=redirect, verify=False, timeout=timeout)
        return resp
    except:
        try:
            return requests.get(f"https://{url}", allow_redirects=redirect, verify=False, timeout=timeout)
        except Exception as e:
            return None
        
def get_cves(cpe, sort_by_epss = False, limit = 10):        
    try:
        params = {
            "cpe23": cpe,
            "count": "false",
            "is_key": "false",
            "sort_by_epss": sort_by_epss,
            "skip": "0",
            "limit": limit,
        }
        resp = requests.get(f'https://cvedb.shodan.io/cves', params=params)
        if resp.status_code in [404]: return []

        resp_json = resp.json()
        cves = resp_json["cves"]

        cve_tuples = []
        for c in cves:
            # cve_dict[c["published_time"]] = c["cve_id"]
            cve_tuples.append((c["published_time"], c["cve_id"]))
        sorted_cves = sorted(cve_tuples, key=lambda x: datetime.strptime(x[0], "%Y-%m-%dT%H:%M:%S"), reverse=True)
        top_cves = [cve_id for _, cve_id in sorted_cves[:limit]]
        return top_cves
    except Exception as e:
        return []
    