import argparse
import asyncssh
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
from rich.live import Live
from rich.console import Console
from src.utilities.utilities import get_classic_overall_progress, get_hosts_from_file
import asyncio
import os
import threading
import time
import re

MAX_FILE_SIZE_MB = 100
MAX_LINE_CHARACTER = 300

history_lock = asyncio.Semaphore(1)
output_lock = threading.Lock()
output_file = ""
output_file_path = ""
module_console = None
history_dict = dict[str, set]()
mount_dict = set()
importance_reg = r"(\d+)⭐"

semaphore = asyncio.Semaphore(1)
timing = False

async def get_all_mounts(ssh: asyncssh.SSHClientConnection, error:bool, verbose:bool, console:Console, host, username):
    """
    Runs findmnt once and retrieves all mounted filesystems.
    Returns a list: [(source, mountpoint)]
    """
    mounts = []
    try:
        result = await ssh.run("findmnt -r -n -o SOURCE,FSTYPE,TARGET", check=True)
        for line in result.stdout.split("\n"):
            if line:
                source, fstype, mountpoint = line.split()
                if fstype == "cifs" or fstype == "nfs4":
                    mounts.append((source, mountpoint))
    except Exception as e:
        if error: console.print(f"{host} | {username} | Get All Mounts Failed")
    return mounts

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
        return file_stat.size / (1024 * 1024)  # Convert bytes to MB
    except Exception as e:
        live.console.print("Error getting file size:", e)
        return None

def print_finding(console, host:str, username:str, rule:SnaffleRule, path:str, findings:list[str]):
    console.print(f"[{rule.triage.value}]\[{host}]\[{username}]\[{rule.importance}]\[{rule.name}][/{rule.triage.value}][white] | {path} | {findings}[/white]")

async def process_file(sftp: asyncssh.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose, path, live:Live, error, show_importance):
    try:
        data = None
        start = time.perf_counter()
        async with await sftp.open(path, "r", errors='ignore') as f:
            data = await f.read()
        if timing: print(f"[D] {host} | {username} | Retrieved File | {path} | {time.perf_counter() - start:.2f} sec")
        if not data: return
        start = time.perf_counter()
        if "\r\n" in data:
            data = data.split("\r\n")
        else:
            data = data.split("\n")

        for line in data:
            if len(line) > MAX_LINE_CHARACTER: continue
            a = rules.enum_content(line, 10, 10)

            if a[0]:
                for rule, findings_list in a[1].items():
                    imp = rule.importance
                    m = re.match(importance_reg, imp)
                    if m:
                        i = m.group(1)
                        if int(i) >= show_importance:
                            print_finding(live.console, host, username, rule, path, findings_list)
                    print_finding(module_console, host, username, rule, path, findings_list)
        if timing: print(f"[D] {host} | {username} | Processed File | {path} | {time.perf_counter() - start:.2f} sec")

    except Exception as e: 
        if error: live.console.print("Process File Error:", e)

async def process_directory(sftp: asyncssh.SFTPClient, host:str, username:str, rules: SnafflerRuleSet, verbose: bool, live:Live, error: bool, show_importance: int, discarded_dirs:list[str], history_file_lock, history_file_set, remote_path=".", depth=0):
    global timing
    try:
        global history_dict
        global output_file_path
        # tasks = []
        dir = await sftp.listdir(remote_path)
        for d in dir:
            if d == "." or d == "..":continue
            item_path = f"{remote_path if remote_path != "/" else ""}/{d}"
            if await sftp.isdir(item_path):
                if item_path in discarded_dirs:
                    if verbose: live.console.print(f"[D] {host} | {username} | Share Discard, skipping | {item_path}")
                    continue
                if not rules.enum_directory(item_path)[0]:continue
                if verbose: live.console.print(f"[D] {host} | {username} | Processing Directory | {item_path}")
                start = time.perf_counter()
                await process_directory(sftp, host, username, rules, verbose, live, error, show_importance, discarded_dirs, history_file_lock, history_file_set, remote_path=item_path, depth=depth+1)
                if timing: print(f"[D] {host} | {username} | Processing Directory | {item_path} | {time.perf_counter() - start:.2f} sec")
            elif await sftp.isfile(item_path):
                if item_path == output_file_path: continue
                async with history_file_lock:
                    if item_path in history_file_set:
                        if verbose: live.console.print(f"[F] {host} | {username} | Already Processed, skipping | {item_path}")
                        continue

                enum_file = rules.enum_file(item_path)
                if verbose: live.console.print(f"[F] {host} | {username} | Processing File | {item_path}")
                if not enum_file[0]:
                    if verbose: live.console.print(f"[F] {host} | {username} | Discarded by {enum_file[1][0].name} | {item_path}")
                    continue
                file_size = await get_file_size_mb(sftp, item_path, error, live)
                if file_size > MAX_FILE_SIZE_MB:
                    if verbose: live.console.print(f"[F] {host} | {username} | File too large: {file_size} MB | {item_path}")
                    continue
                if not await can_read_file(sftp, item_path):
                    if verbose: live.console.print(f"[F] {host} | {username} | Read Failed | {item_path}")
                    continue
                    
                    
                async with history_file_lock:
                    history_file_set.add(item_path)

                for rule, findings_list in enum_file[1].items():
                    imp = rule.importance
                    
                    m = re.match(importance_reg, imp)
                    if m:
                        i = m.group(1)
                        if int(i) >= show_importance:
                            print_finding(live.console, host, username, rule, item_path, findings_list)
                    print_finding(module_console, host, username, rule, item_path, findings_list)
                if verbose: live.console.print(f"[F] {item_path}")
                start = time.perf_counter()
                await process_file(sftp, host, username, rules, verbose, item_path, live, error, show_importance)
                if timing: print(f"[D] {host} | {username} | Processing File | {item_path} | {time.perf_counter() - start:.2f} sec")

    except Exception as e:
        if error: live.console.print("Process Directory Error:", e)

async def process_host(ip, port, username, password, rules: SnafflerRuleSet, verbose, live:Live, error, show_importance, history_file_lock, history_file_set):
    """Main function to process a single SSH host asynchronously."""
    try:
        async with semaphore:
            async with await asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, client_keys=None, keepalive_interval=10) as conn:
                if verbose: live.console.print(f"Connected to {ip}:{port}")
                mounts = await get_all_mounts(conn, error, verbose, live.console, f"{ip}:{port}", username)
                discarded_dirs = []
                async with history_lock:
                    for mount in mounts:
                        if mount[0] in mount_dict:
                            discarded_dirs.append(mount[1])
                            continue
                        mount_dict.add(mount[0])
                        
                sftp = await conn.start_sftp_client()
                await process_directory(sftp, f"{ip}:{port}", username, rules, verbose, live, error, show_importance, discarded_dirs, history_file_lock, history_file_set,remote_path="/", depth=0)

                
    except Exception as e:
        if error: print(f"Error processing {ip}:{port}: {e}")

async def main2():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("-o", "--output", type=str, required=True, help="Output File.")
    parser.add_argument("--show-importance", type=int, default=0, help="Print only snaffles that is above given importance level, does NOT affect output to file.")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--timing", action="store_true", help="Print our timings of functions")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser.add_argument("-e", "--error", action="store_true", help="Prints errors")
    
    args = parser.parse_args()
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SSH Snaffle")
    console = Console(force_terminal=True)    
    global semaphore
    semaphore = asyncio.Semaphore(args.threads)
    
    global output_file, output_file_path, module_console,timing

    timing = args.timing
    output_file = args.output
    try:
        with open(output_file, "w") as f:
            output_file_path = os.path.abspath(f.name)
            module_console = Console(force_terminal=True, record=True, file=f)    
            rules = SnafflerRuleSet.load_default_ruleset()


            with Live(overall_progress, console=console) as live:
                overall_progress.update(overall_task_id, total=len(get_hosts_from_file(args.file)), completed=0)
                
                host_lock_dict = dict[str, asyncio.Semaphore]()
                host_files_dict = dict[str, set]()
                try:
                    async with asyncio.TaskGroup() as tg:
                        tasks = []
                        for entry in get_hosts_from_file(args.file):
                            host, cred = entry.split(" => ")
                            ip, port = host.split(":")
                            username, password = cred.split(":")
                            if host not in host_lock_dict:
                                host_lock_dict[host] = asyncio.Semaphore(1)
                                host_files_dict[host] = set()
                                
                            tasks.append(tg.create_task(process_host(ip, port, username, password, rules, args.verbose, live, args.error, args.show_importance, host_lock_dict[host], host_files_dict[host])))
                        overall_progress.start_task(overall_task_id)
                        for task in asyncio.as_completed(tasks):
                            await task
                            overall_progress.update(overall_task_id, total=len(get_hosts_from_file(args.file)), advance=1)
                except Exception as e:
                    print("TaskGroup error", e)

    except Exception as e: 
        if args.error: 
            print("Main2 error", e)

def main():
    asyncio.run(main2())