import argparse
import pprint
from tabnanny import verbose
import paramiko
import stat
import sys
import asyncssh
import rich.progress
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet

from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich import progress
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
import asyncio
import os
import multiprocessing
import threading
import rich
from concurrent.futures import ProcessPoolExecutor
import time
from colorama import init, Fore

MAX_FILE_SIZE_MB = 100
MAX_LINE_CHARACTER = 300
console = Console()
output_lock = multiprocessing.Lock()
output_file = ""
output_file_path = ""
module_console = None
history_dict = dict[str, set]()

def can_read_file(sftp: paramiko.SFTPClient, path):
    """Attempts to open a remote file in read mode to check permissions."""
    try:
        with sftp.open(path, "r") as f:
            f.read(1)  # Try reading a byte
        return True
    except PermissionError:
        return False
    except Exception as e:
        return False

def get_file_size_mb(sftp: paramiko.SFTPClient, path, error):
    """Returns the size of a remote file in MB."""
    try:
        file_size_bytes = sftp.stat(path).st_size
        return file_size_bytes / (1024 * 1024)  # Convert bytes to MB
    except Exception as e:
        if error: console.print("Error getting file size:", e)
        return None

def print_finding(host:str, username:str, rule:SnaffleRule, path:str, findings:list[str]):
    console.print(f"[{rule.triage.value}]\[{host}]\[{username}]\[{rule.importance}]\[{rule.name}][/{rule.triage.value}][white] | {path} | {findings}[/white]")

def process_file(sftp: paramiko.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, path, error):
    try:
        with sftp.open(path) as f:
            data = f.read().decode("utf-8")

            if "\r\n" in data:
                data = data.split("\r\n")
            else:
                data = data.split("\n")

            for line in data:
                if len(line) > MAX_LINE_CHARACTER: continue
                a = rules.enum_content(line, 10, 10)

                if a[0]:
                    for b,c in a[1].items():
                        print_finding(host, username, b, path, c)
    except Exception as e:
        if error: console.print("Process File Error:", e)

def process_directory(sftp: paramiko.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, error, history_lock, history_dict, remote_path=".", depth=0):
    try:
        dir = sftp.listdir(remote_path)
        for d in dir:
            try:
                item_path = f"{remote_path if remote_path != "/" else ""}/{d}"                
                if stat.S_ISDIR(sftp.stat(item_path).st_mode):
                    if not rules.enum_directory(item_path)[0]:continue
                    if verbose: console.print(f"[D] {host} | {username} | {item_path}")

                    process_directory(sftp, host, username, rules, verbose, error, history_lock, history_dict, item_path, depth=depth+1)
                elif stat.S_ISREG(sftp.stat(item_path).st_mode):
                    if item_path == output_file_path: continue
                    if verbose: console.print(f"[F] {host} | {username} | Pre-Processing | {item_path}")
                    """
                    with history_lock:
                        print(history_dict[host])
                        if item_path in history_dict[host]:
                            if verbose: console.print(f"[F] {host} | {username} | Already processed, skipping | {item_path}")
                            continue
                    """
                    enum_file = rules.enum_file(item_path)
                    if not enum_file[0]:
                        if verbose: console.print(f"[F] {host} | {username} | Discarded by {enum_file[1][0].name} | {item_path}")
                        continue
                    file_size = get_file_size_mb(sftp, item_path, error)
                    if file_size > MAX_FILE_SIZE_MB:
                        if verbose: console.print(f"[F] {host} | {username} | File too large: {file_size} MB | {item_path}")
                        continue
                    if not can_read_file(sftp, item_path):
                        if verbose: console.print(f"[F] {host} | {username} | Read Failed | {item_path}")
                        continue
                    """
                    with history_lock:
                        with history_dict.get(host, set()) as shared_set:
                            shared_set.add(item_path)
                            history_dict[host] = shared_set  # Update the dictionary
                        #history_dict[host].add(item_path)
                    """
                    for b,c in enum_file[1].items():
                        print_finding(host, username, b, item_path, c)

                    if verbose: console.print(f"[F] {host} | {username} | Processing | {item_path}")
                    process_file(sftp, host, username, rules, verbose, item_path, error)
            except Exception as e:
                if error: console.print(f"Process Directory Error for: {host} with user {username} for path {remote_path}: {e}")

    except Exception as e:
        if error: console.print(f"Process Directory Error for: {host} with user {username} for path {remote_path}: {e}")
    

async def connect_ssh(hostname, port, username, password):
    """Asynchronously establishes an SSH connection."""
    return await asyncssh.connect(hostname, port=port, username=username, password=password, known_hosts=None, client_keys=None)

def process_host(ip, port, username, password, rules: SnafflerRuleSet, verbose, error, history_lock, history_dict):
    """Main function to process a single SSH host asynchronously."""
    client = None
    sftp = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=int(port),username=username, password=password, timeout=10)
        sftp = client.open_sftp()
        console.print(f"Starting Processing {ip}:{port} as user {username}")
        process_directory(sftp, f"{ip}:{port}", username, rules, verbose, error, history_lock, history_dict, "/")
        console.print(f"Ending Processing {ip}:{port} as user {username}")
        sftp.close()
        client.close()
            
    except Exception as e:
        if error: console.print(f"Error processing {ip}:{port} as user {username}: {e}")
        if sftp: sftp.close()
        if client: client.close()
        

def main3():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("-o", "--output", type=str, required=True, help="Output File.")
    parser.add_argument("--show-importance", type=int, default=0, help="Print only snaffles that is above given importance level, does NOT affect output to file.")
    parser.add_argument("-t","--thread", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser.add_argument("-e", "--error", action="store_true", help="Prints errors")
    
    args = parser.parse_args()   
    
    output_file = args.output
    futures = []
    rules = SnafflerRuleSet.load_default_ruleset()

    with multiprocessing.Manager() as manager:
        history_lock = manager.Lock()
        history_dict = manager.dict()
        with ProcessPoolExecutor(max_workers=args.thread) as executor:
            for entry in get_hosts_from_file(args.file):
                host, cred = entry.split(" => ")
                ip, port = host.split(":")
                username, password = cred.split(":")
                history_dict[host] = set()
                futures.append(executor.submit(process_host, ip, port, username, password, rules, args.verbose, args.error, history_lock, history_dict))
            start_time = time.time()
            for future in futures:
                future.result()
            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Function took {execution_time:.4f} seconds to execute.")




def main():
    main3()