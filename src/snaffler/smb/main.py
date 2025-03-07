from impacket.smbconnection import SMBConnection
import argparse
from src.snaffler.customsnaffler.rule import SnaffleRule
from src.snaffler.customsnaffler.ruleset import SnafflerRuleSet
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.console import Group
from rich.panel import Panel
from rich.live import Live
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import threading

MAX_FILE_SIZE_MB = 100
MAX_LINE_CHARACTER = 300
output_lock = threading.Lock()
output_file = ""
output_file_path = ""
module_console = None

history_lock = threading.Lock()

history_dict = dict[str, set]()

def multithread_export_print(console: Console):
    with output_lock:
        a = console.export_text(styles=True)
        with open(output_file, "a") as f:
            f.write(a)

def process_file(conn, share, file, host, username, rules, error, verbose, live):
    def process_file2(data):
        data = data.decode("utf-8", "ignore")
        if "\r\n" in data:
            data = data.split("\r\n")
        else:
            data = data.split("\n")
        for line in data:
            if len(line) > MAX_LINE_CHARACTER: continue
            a = rules.enum_content(line, 10, 10)

            if a[0]:
                for b,c in a[1].items():
                    print_finding(live.console, host, share, username, b, file, c)
                    print_finding(module_console, host, share, username, b, file, c)
                multithread_export_print(module_console)
    try:

        conn.getFile(share, file, process_file2)
    except Exception as e: 
        if error: print("Process File Error:", e)



def can_read_file(conn, share, file, verbose, error, live):
    def can_read_file2(data):
        pass
    try:
        conn.getFile(share, file, can_read_file2)
        return True
    except Exception as e: 
        if error:live.console.print("Can read file error", e)
    
def print_finding(console, host:str, share:str, username:str, rule:SnaffleRule, path:str, findings:list[str]):
    console.print(f"[{rule.triage.value}]\[{host}]\[{share}]\[{username}]\[{rule.importance}]\[{rule.name}][/{rule.triage.value}][white] | {path} | {findings}[/white]")

def list_files_recursively(conn, share, rules, target, username, error, verbose, live, directory="*"):
    """
    Recursively lists all files and directories in a given SMB share.
    """
    try:
        # List contents of the current directory
        files = conn.listPath(share, directory)
        for file in files:
            filename = file.get_longname()
            if filename in [".", ".."]:  # Skip current and parent directory links
                continue

            item_path = directory.replace("*", "")  + filename
            
            if file.is_directory():
                if not rules.enum_directory(item_path)[0]:continue
                if verbose: live.console.print(f"[DIR] {item_path}")
                # Recursively list the contents of subdirectories
                list_files_recursively(conn, share, rules, target, username, error, verbose, live, item_path + "/*")
            else:
                if file.get_filesize() / 1024 > MAX_FILE_SIZE_MB: continue
                with history_lock:
                    if item_path in history_dict[f"{target}{share}"]: 
                        if verbose: live.console.print(f"[F] | Already processed, skipping | {item_path}")
                        continue
                enum_file = rules.enum_file(item_path)
                if verbose: live.console.print(f"[F] | Processing | {item_path}")
                if not enum_file[0]:
                    if verbose: live.console.print(f"[F] | Discarded by {enum_file[1][0].name} | {item_path}")
                    continue
                if file.get_filesize() / 1024 > MAX_FILE_SIZE_MB:
                    if verbose: live.console.print(f"[F] | File too large: {file.get_filesize() / 1024} MB | {item_path}")
                    continue
                if not can_read_file(conn, share, item_path, verbose, error, live):
                    if verbose: live.console.print(f"[F] | Read Failed | {item_path}")
                    continue

                with history_lock:
                    history_dict[f"{target}{share}"].add(item_path)
                    
                for b,c in enum_file[1].items():
                    print_finding(live.console, target, share, username, b, item_path, c)
                    print_finding(module_console, target, share, username, b, item_path, c)
                multithread_export_print(module_console)
                if verbose: live.console.print(f"[FILE] {item_path}")
                process_file(conn, share, item_path, target, username, rules, error, verbose, live)

    except Exception as e:
        if error:live.console.print(f"Error accessing {directory}: {e}")


def process_host(target, username, password, rules, verbose, live, error):
    try:
        # Establish SMB connection
        conn = SMBConnection(target, target)
        conn.login(username, password)
        
        for share in conn.listShares():
            try:
                history_dict[f"{target}{share['shi1_netname'][:-1]}"] = set()
                list_files_recursively(conn, share['shi1_netname'][:-1], rules, target, username, error, verbose, live)
            except Exception as e:
                if live.console.print: print(f"Failed list share {share['shi1_netname'][:-1]} on {target}: {e}")

        conn.close()
    except Exception as e:
        if error: live.console.print(f"Failed to connect: {e}")

def main():
    parser = argparse.ArgumentParser(description="Snaffle via SMB.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("-cf", "--cred-file", type=str, required=True, help="Input file name, format is 'username:password'")
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
    overall_task_id = overall_progress.add_task("", start=False, modulename="SMB Snaffle")
    console = get_classic_console(force_terminal=True)
    
    progress_group = Group(
        Panel(single_progress, title="SMB Snaffle", expand=False),
        overall_progress,
    ) if not args.only_show_progress else Group(overall_progress)
    
    global output_file, output_file_path, module_console
    

    output_file = args.output
    with open(output_file, "w") as f:
        output_file_path = os.path.abspath(f.name)
        module_console = Console(force_terminal=True, record=True, file=f)
        rules = SnafflerRuleSet.load_default_ruleset()
        
        with Live(progress_group, console=console) as live:
            overall_progress.update(overall_task_id, total=len(get_hosts_from_file(args.file)) * len(get_hosts_from_file(args.cred_file)), completed=0)
            overall_progress.start_task(overall_task_id)
            futures = []
            tasks = []
            with ThreadPoolExecutor(args.threads) as executor:
                for cred in get_hosts_from_file(args.cred_file):
                    for host in get_hosts_from_file(args.file):
                        ip, port = host.split(":")
                        username, password = cred.split(":")
                        # single_task_id = single_progress.add_task("single", start=False, host=host, status="status", total=1)
                        future = executor.submit(process_host(ip, username, password, rules, args.verbose, live, args.error))
                        futures.append(future)
                for a in as_completed(futures):
                    overall_progress.update(overall_task_id, advance=1)
