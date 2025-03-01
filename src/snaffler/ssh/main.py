import argparse
from genericpath import isfile
from os import remove
import pprint
from tabnanny import verbose
import paramiko
import stat
import sys
import asyncssh
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
import threading
from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
import signal
import asyncio

stop_event = threading.Event()

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

def process_file(sftp: asyncssh.SFTPClient, rules: SnafflerRuleSet, path:str, host:str, username:str):
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

def list_remote_directory(sftp:asyncssh.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, remote_path=".", depth=0):
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
                    

                    process_file(sftp, rules, item_path, host, username)
        except Exception as e: print(e)

def signal_handler(sig, frame):
    """Handles CTRL+C (SIGINT) to stop all threads cleanly."""
    print("\nCTRL+C detected! Stopping all threads...")
    stop_event.set()  # Signal threads to stop



async def process_directory(sftp: asyncssh.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, remote_path=".", depth=0):
    try:
        dir = await sftp.readdir(remote_path)
        for d in dir:
            if d.filename == "." or d.filename == "..":continue
            item_path = f"{remote_path if remote_path != "/" else ""}/{d.filename}"
            if await sftp.isdir(item_path):
                print("  " * depth + f"[D] {item_path}")
                await process_directory(sftp, host, username, rules, verbose, item_path, depth=depth+1)
            elif await sftp.isfile(item_path):
                print("  " * depth + f"[F] {item_path}")
    except Exception as e: print(e)
    

async def connect_ssh(hostname, port, username, password):
    """Asynchronously establishes an SSH connection."""
    return await asyncssh.connect(hostname, port=port, username=username, password=password, known_hosts=None, client_keys=None)

async def process_host(hostname, port, username, password, rules: SnafflerRuleSet):
    """Main function to process a single SSH host asynchronously."""
    try:
        async with await connect_ssh(hostname, port, username, password) as conn:
            print(f"Connected to {hostname}")

            sftp = await conn.start_sftp_client()
            await process_directory(sftp, f"{hostname}:{port}", username, rules, verbose, "/")
            
    except Exception as e:
        print(f"Error processing {hostname}: {e}")

async def main2():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    
    args = parser.parse_args()
    signal.signal(signal.SIGINT, signal_handler)
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
        tasks = []
        for entry in get_hosts_from_file(args.file):
            host, cred = entry.split(" => ")
            ip, port = host.split(":")
            username, password = cred.split(":")
            tasks.append(process_host(ip, port, username, password, rules))
            

        await asyncio.gather(*tasks)
        """
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
        """

def main():
    asyncio.run(main2())