import argparse
from ast import For
import pprint
from tabnanny import verbose
import paramiko
import stat
import sys
import asyncssh
import rich.progress
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
from src.snaffler.customsnaffler.constants import Triage
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
history_lock = multiprocessing.Lock()
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

def get_file_size_mb(sftp: paramiko.SFTPClient, path, error, live):
    """Returns the size of a remote file in MB."""
    try:
        file_size_bytes = sftp.stat(path).st_size
        return file_size_bytes.size / (1024 * 1024)  # Convert bytes to MB
    except Exception as e:
        if error: live.console.print("Error getting file size:", e)
        return None

def print_finding(host:str, username:str, rule:SnaffleRule, path:str, findings:list[str]):
    color = Fore.GREEN
    match rule.triage:
        case Triage.Triage.Green:
            color = Fore.GREEN
        case Triage.Triage.Orange1:
            color = "\033[38;5;214m"
        case Triage.Triage.Red:
            color = Fore.RED
        case Triage.Triage.Blue:
            color = Fore.BLUE
        case Triage.Triage.Yellow:
            color = Fore.YELLOW
    print(color + f"[{rule.triage.value}]\[{host}]\[{username}]\[{rule.importance}]\[{rule.name}]" + Fore.WHITE + f" | {path} | {findings}")

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
        if error: print("Process File Error:", e)

def process_directory(sftp: paramiko.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, error, remote_path=".", depth=0):
    try:
        dir = sftp.listdir(remote_path)
        for d in dir:
            try:
                item_path = f"{remote_path if remote_path != "/" else ""}/{d}"
                if verbose: print(f"Processing {host}:{item_path}")
                
                if stat.S_ISDIR(sftp.stat(item_path).st_mode):
                    if not rules.enum_directory(item_path)[0]:continue
                    # if verbose: console.print(f"[D] {item_path}")

                    process_directory(sftp, host, username, rules, verbose, error, item_path, depth=depth+1)
                elif stat.S_ISREG(sftp.stat(item_path).st_mode):
                    # if item_path == output_file_path: continue
                    """
                    with history_lock:
                        if item_path in history_dict[host]:
                            if verbose: print(f"[F] | Already processed, skipping | {item_path}")
                            continue
                    """

                    enum_file = rules.enum_file(item_path)
                    if verbose: print(f"[F] | Processing | {item_path}")
                    if not enum_file[0]:
                        if verbose: print(f"[F] | Discarded by {enum_file[1][0].name} | {item_path}")
                        continue
                    file_size = get_file_size_mb(sftp, item_path, error)
                    if file_size > MAX_FILE_SIZE_MB:
                        if verbose: print(f"[F] | File too large: {file_size} MB | {item_path}")
                        continue
                    if not can_read_file(sftp, item_path):
                        if verbose: print(f"[F] | Read Failed | {item_path}")
                        continue

                    """
                    with history_lock:
                        history_dict[host].add(item_path)
                    """

                    for b,c in enum_file[1].items():
                        print_finding(host, username, b, item_path, c)

                    if verbose: print(f"[F] {item_path}")
                    process_file(sftp, host, username, rules, verbose, item_path, error)
            except Exception as e:
                if error: print(f"Process Directory Error for: {host} with user {username} for path {remote_path}: {e}")

    except Exception as e:
        if error: print(f"Process Directory Error for: {host} with user {username} for path {remote_path}: {e}")
    

def process_host(ip, port, username, password, rules: SnafflerRuleSet, verbose, error):
    """Main function to process a single SSH host asynchronously."""
    init(autoreset=True)
    console.print("[blue]HEHE[/blue]")
    try:
        client = paramiko.SSHClient()
        
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=int(port),username=username, password=password, timeout=10)
        sftp = client.open_sftp()
        process_directory(sftp, f"{ip}:{port}", username, rules, verbose, error, "/")
        client.close()
            
    except Exception as e:
        print(f"Error processing {ip}:{port}: {e}")

async def main2():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("-o", "--output", type=str, required=True, help="Output File.")
    parser.add_argument("--show-importance", type=int, default=0, help="Print only snaffles that is above given importance level, does NOT affect output to file.")
    parser.add_argument("-t","--thread", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser.add_argument("-e", "--error", action="store_true", help="Prints errors")
    
    args = parser.parse_args()
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SSH Snaffle")
    console = Console(force_terminal=True)
    global semaphore
    semaphore = asyncio.Semaphore(args.thread)
    
    global output_file, output_file_path, module_console
    module_console = Console(force_terminal=True, record=True, quiet=True)    
    

    output_file = args.output
    with open(output_file, "w") as f:
        output_file_path = os.path.abspath(f.name)
        module_console = Console(force_terminal=True, record=True, file=f)    
        rules = SnafflerRuleSet.load_default_ruleset()


        with Live(overall_progress, console=console) as live:
            overall_progress.update(overall_task_id, total=len(get_hosts_from_file(args.file)), completed=0)
            overall_progress.start_task(overall_task_id)

            tasks = []

            for entry in get_hosts_from_file(args.file):
                host, cred = entry.split(" => ")
                ip, port = host.split(":")
                username, password = cred.split(":")
                
                tasks.append(asyncio.create_task(process_host(ip, port, username, password, rules, args.verbose, live, args.error)))
            
            await asyncio.gather(*tasks)  # Wait for all tasks to complete


def process_host2(data):
    """Main function to process a single SSH host asynchronously."""
    print("c")
    return
    try:
        print(data)
        hostname = data["hostname"]
        print(2)
        port = data["port"]
        print(3)
        username = data["username"]
        print(4)
        password = data["password"]
        print(5)
        verbose = data["verbose"]
        print(6)
        live = data["live"]
        print(7)
        rules = data["rules"]
        print(8)
        error = data["error"]
        print(9)
        ip = data["ip"]
        print(0)
        client = paramiko.SSHClient()
        
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=int(port),username=username, password=password, timeout=10)
        sftp = client.open_sftp()
        process_directory(sftp, hostname, username, rules, verbose, live, error, "/")
        client.close()
            
    except Exception as e:
        print(e)
        if error: live.console.print(f"Error processing {hostname}: {e}")



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
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SSH Snaffle")
    console = Console(force_terminal=True)

    
    module_console = Console(force_terminal=True, record=True, quiet=True)    
    
    output_file = args.output
    futures = []
    rules = SnafflerRuleSet.load_default_ruleset()
    with ProcessPoolExecutor(max_workers=args.thread) as executor:
        for entry in get_hosts_from_file(args.file):
            host, cred = entry.split(" => ")
            ip, port = host.split(":")
            username, password = cred.split(":")
            futures.append(executor.submit(process_host, ip, port, username, password, rules, args.verbose, args.error))
        start_time = time.time()
        for future in futures:
            future.result()
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Function took {execution_time:.4f} seconds to execute.")
    """
    with overall_progress as progress:
        futures = []  # keep track of the jobs
        with multiprocessing.Manager() as manager:
            # this is the key - we share some state between our 
            # main process and our worker functions
            _progress = manager.dict()
            overall_progress_task = progress.add_task("[green]All jobs progress:", modulename="something")

            with ProcessPoolExecutor(max_workers=args.thread) as executor:
                for entry in get_hosts_from_file(args.file):
                    host, cred = entry.split(" => ")
                    ip, port = host.split(":")
                    username, password = cred.split(":")
                    task_id = progress.add_task(f"task", visible=False, modulename="something1")
                    futures.append(executor.submit(process_host, ip, port, username, password, rules, args.verbose, args.error))


                # monitor the progress:
                while (n_finished := sum([future.done() for future in futures])) < len(
                    futures
                ):
                    progress.update(
                        overall_progress_task, completed=n_finished, total=len(futures)
                    )
                    for task_id, update_data in _progress.items():
                        latest = update_data["progress"]
                        total = update_data["total"]
                        # update the progress bar for this task:
                        progress.update(
                            task_id,
                            completed=latest,
                            total=total,
                            visible=latest < total,
                        )

                # raise any errors:
                for future in futures:
                    future.result()
                    # progress.update(overall_progress_task, advance=1)
    """
            



def main():
    main3()