import argparse
import pprint
import paramiko
import stat
import sys
import asyncssh
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
import asyncio
import os
import threading

MAX_FILE_SIZE_MB = 100
MAX_LINE_CHARACTER = 300

history_lock = threading.Lock()
output_lock = threading.Lock()
output_file = ""
output_file_path = ""
module_console = None
history_dict = dict[str, set]()


def multithread_export_print(console: Console):
    with output_lock:
        a = console.export_text(styles=True)
        with open(output_file, "a") as f:
            f.write(a)


async def can_read_file(sftp, path):
    """Attempts to open a remote file in read mode to check permissions."""
    try:
        async with sftp.open(path, "r") as f:
            await f.read(1)  # Try reading a byte
        return True
    except PermissionError:
        return False
    except Exception as e:
        return False

async def get_file_size_mb(sftp, path, error, live):
    """Returns the size of a remote file in MB."""
    try:
        file_stat = await sftp.stat(path)
        size_mb = file_stat.size / (1024 * 1024)  # Convert bytes to MB
        return size_mb  # Round to 2 decimal places
    except Exception as e:
        live.console.print("Error getting file size:", e)
        return None

def print_finding(console, host:str, username:str, rule:SnaffleRule, path:str, findings:list[str]):
    console.print(f"[{rule.triage.value}]\[{host}]\[{username}]\[{rule.importance}]\[{rule.name}][/{rule.triage.value}][white] | {path} | {findings}[/white]")

async def process_file(sftp: asyncssh.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, path, live:Live, error):
    try:
        async with await sftp.open(path, errors='ignore') as f:
            data = await f.read()

            if "\r\n" in data:
                data = data.split("\r\n")
            else:
                data = data.split("\n")

            for line in data:
                if len(line) > MAX_LINE_CHARACTER: continue
                a = rules.enum_content(line, 10, 10)

                if a[0]:
                    for b,c in a[1].items():
                        print_finding(live.console, host, username, b, path, c)
                        print_finding(module_console, host, username, b, path, c)
                    multithread_export_print(module_console)
    except Exception as e: 
        if error: live.console.print("Process File Error:", e)

async def process_directory(sftp: asyncssh.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, live:Live, error, remote_path=".", depth=0):
    try:
        tasks = []
        dir = await sftp.readdir(remote_path)
        for d in dir:
            if d.filename == "." or d.filename == "..":continue
            item_path = f"{remote_path if remote_path != "/" else ""}/{d.filename}"
            if await sftp.isdir(item_path):
                if not rules.enum_directory(item_path)[0]:continue
                if verbose: live.console.print(f"[D] {item_path}")
                # tasks.append(process_directory(sftp, host, username, rules, verbose, live, error, item_path, depth=depth+1))
                await process_directory(sftp, host, username, rules, verbose, live, error, item_path, depth=depth+1)
            elif await sftp.isfile(item_path):
                if item_path == output_file_path: continue
                enum_file = rules.enum_file(item_path)
                if verbose: live.console.print(f"[F] | Processing | {item_path}")
                if not enum_file[0]:
                    if verbose: live.console.print(f"[F] | Discarded by {enum_file[1][0].name} | {item_path}")
                    continue
                file_size = await get_file_size_mb(sftp, item_path, error, live)
                if file_size > MAX_FILE_SIZE_MB:
                    if verbose: live.console.print(f"[F] | File too large: {file_size} MB | {item_path}")
                    continue
                if not await can_read_file(sftp, item_path):
                    if verbose: live.console.print(f"[F] | Read Failed | {item_path}")
                    continue

                with history_lock:
                    if item_path in history_dict[host]:
                        if verbose: live.console.print(f"[F] | Already processed, skipping | {item_path}")
                        continue
                    history_dict[host].add(item_path)
                    
                for b,c in enum_file[1].items():
                    print_finding(live.console, host, username, b, item_path, c)
                    print_finding(module_console, host, username, b, item_path, c)
                multithread_export_print(module_console)
                if verbose: live.console.print(f"[F] {item_path}")
                await process_file(sftp, host, username, rules, verbose, item_path, live, error)
                #tasks.append(process_file(sftp, host, username, rules, verbose, item_path, live, error))
        await asyncio.gather(*tasks)
    except Exception as e:
        if error: live.console.print("Process Directory Error:", e)
    

async def connect_ssh(hostname, port, username, password):
    """Asynchronously establishes an SSH connection."""
    return await asyncssh.connect(hostname, port=port, username=username, password=password, known_hosts=None, client_keys=None)

async def process_host(hostname, port, username, password, rules: SnafflerRuleSet, verbose, live:Live, error):
    """Main function to process a single SSH host asynchronously."""
    try:
        async with await connect_ssh(hostname, port, username, password) as conn:
            if verbose: live.console.print(f"Connected to {hostname}:{port}")
            history_dict[f"{hostname}:{port}"] = set()
            sftp = await conn.start_sftp_client()
            await process_directory(sftp, f"{hostname}:{port}", username, rules, verbose, live, error, "/")
            
    except Exception as e:
        print(f"Error processing {hostname}: {e}")

async def main2():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("-o", "--output", type=str, required=True, help="Output File")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser.add_argument("-e", "--error", action="store_true", help="Prints errors")
    
    args = parser.parse_args()
    overall_progress = get_classic_overall_progress()
    single_progress = get_classic_single_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SSH Snaffle")
    console = Console(force_terminal=True)    
    
    progress_group = Group(
        Panel(single_progress, title="SSH Snaffle", expand=False),
        overall_progress,
    ) if not args.only_show_progress else Group(overall_progress)
    
    global output_file, output_file_path, module_console
    module_console = Console(force_terminal=True, record=True, quiet=True)    
    

    output_file = args.output
    with open(output_file, "w") as f:
        output_file_path = os.path.abspath(f.name)
        module_console = Console(force_terminal=True, record=True, file=f)    
        rules = SnafflerRuleSet.load_default_ruleset()


        with Live(progress_group, console=console) as live:
            overall_progress.update(overall_task_id, total=len(get_hosts_from_file(args.file)), completed=0)
            overall_progress.start_task(overall_task_id)
            futures = []
            tasks = []

            with ThreadPoolExecutor(args.threads) as executor:
                for entry in get_hosts_from_file(args.file):
                    host, cred = entry.split(" => ")
                    ip, port = host.split(":")
                    username, password = cred.split(":")
                    future = executor.submit(await process_host(ip, port, username, password, rules, args.verbose, live, args.error))
                    futures.append(future)
                for a in as_completed(futures):
                    overall_progress.update(overall_task_id, advance=1)

def main():
    asyncio.run(main2())