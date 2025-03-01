import argparse
import pprint
import paramiko
import stat
import sys
from paramiko import SFTPClient
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
import threading
from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file

def ssh_connect(host, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, int(port), username, password)
        return client
    except Exception as e:
        print(f"[!] SSH Connection failed: {e}")
        return None

def is_remote_file(sftp, path):
    """Checks if a given remote path is a file."""
    try:
        file_stat = sftp.stat(path)
        return stat.S_ISREG(file_stat.st_mode)  # Checks if it's a regular file
    except FileNotFoundError:
        return False  # File does not exist

def is_remote_directory(sftp, path):
    """Checks if the given remote path is a directory (excluding special files)."""
    try:
        file_stat = sftp.stat(path)
        return stat.S_ISDIR(file_stat.st_mode)  # Proper check for directories
    except FileNotFoundError:
        return False  # Path does not exist

def process_file(sftp: SFTPClient, rules: SnafflerRuleSet, path:str, host:str, username:str):
    try:
        with sftp.open(path, "r") as f:
            data = f.read()
            try:
                # Try decoding as UTF-8
                data = data.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                pass

            a = rules.parse_file(data, 10, 10)
            # print(data)
            if a[0]:
                for b,c in a[1].items():
                    print(f"{host} - {username} => {path} - {b.name} - {c}")
    except Exception as e: print(f"Process file error: {e}")

def list_remote_directory(sftp: SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, remote_path=".", depth=0):
    threads = []
    """Recursively lists all files and directories in the given remote path."""
    try:
        items = sftp.listdir_attr(remote_path)
    except Exception: return
    
    for item in items:
        try:
            item_path = f"{remote_path if remote_path != "/" else ""}/{item.filename}"
            # If the item is a directory, recursively list its contents
            if is_remote_directory(sftp, item_path):  # Check if it's a directory
                if not rules.enum_directory(item_path)[0]:continue
                if verbose: print("  " * depth + f"[D] {item_path}")
                list_remote_directory(sftp, host, username, rules, verbose, item_path, depth + 1)
            else:
                if is_remote_file(sftp, item_path): 
                    
                    enum_file = rules.enum_file(item_path)
                    if not enum_file[0]:continue
                    if verbose: print("  " * depth + f"[F] {item_path}")

                    for b,c in enum_file[1].items():
                        print(f"{host} - {username} => {item_path} - {b.name} - {c}")
                    
                    # thread = threading.Thread(target=process_file, args=(sftp, rules, item_path, host, username,))
                    # thread.start()
                    # threads.append(thread)
                    process_file(sftp, rules, item_path, host, username)
        except Exception as e: print(e)
    
    if verbose and len(threads) > 0: print(f"Waiting threads to finish for path: {remote_path}")
    for thread in threads:
        thread.join()
    if verbose and len(threads) > 0: print(f"Threads finished for path: {remote_path}")

            

def main():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    
    args = parser.parse_args()
    
    overall_progress = get_classic_overall_progress()
    single_progress = get_classic_single_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SSH Snaffle")
    console = get_classic_console(force_terminal=True)
    
    progress_group = Group(
        Panel(single_progress, title="SSH Snaffle", expand=False),
        overall_progress,
    ) if not args.only_show_progress else Group(overall_progress)
    
    rules = SnafflerRuleSet.load_default_ruleset()

    with Live(progress_group, console=console):
        overall_progress.update(overall_task_id, total=len(get_hosts_from_file(args.file)), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []

        with ThreadPoolExecutor(args.threads) as executor:
            for entry in get_hosts_from_file(args.file):
                host, cred = entry.split(" => ")
                ip, port = host.split(":")
                username, password = cred.split(":")
                client = ssh_connect(ip, port, username, password)
                if not client: continue
                sftp = client.open_sftp()
                single_task_id = single_progress.add_task("single", start=False, host=host, status="status", total=1)
                future = executor.submit(list_remote_directory, sftp, host, username, rules, args.verbose, "/")
                futures.append(future)
            for a in as_completed(futures):
                overall_progress.update(overall_task_id, advance=1)
