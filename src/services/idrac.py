import argparse
import subprocess
import re
from impacket.smbconnection import SMBConnection
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.services.service import Vuln_Data
from rich.console import Group
from rich.panel import Panel
import requests

class Version_Vuln_Data(Vuln_Data):
    def __init__(self, host: str, version: str):
        self.host = host
        self.version = version

def version_single(single_progress: Progress, single_task_id: TaskID, console: Console, host: str, output: str, timeout: int, verbose: bool):
    try:
        try:
            resp = requests.get(f"https://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False, timeout=timeout)
        except:
            try:
                resp = requests.get(f"http://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False, timeout=timeout)
            except: return
        
        version = resp.json()["Attributes"]["FwVer"]
        return Version_Vuln_Data(host, version)
    except:return

def version_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False, only_show_progress: bool = False):
    versions = {}
    
    overall_progress = get_classic_overall_progress()
    single_progress = get_classic_single_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="IDRAC Version")
    console = get_classic_console(force_terminal=True)
    
    progress_group = Group(
        Panel(single_progress, title="IDRAC Version", expand=False),
        overall_progress,
    ) if not only_show_progress else Group(overall_progress)
    
    with Live(progress_group, console=console):
        overall_progress.update(overall_task_id, total=len(l), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[Version_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                single_task_id = single_progress.add_task("single", start=False, host=host, status="status", total=1)
                future = executor.submit(version_single, single_progress, single_task_id, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                overall_progress.update(overall_task_id, advance=1)
                results.append(a.result())
    for r in results:
        if not r: continue
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)

    if len(versions) > 0:
        print("Detected iDRAC versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")

def version_console(args):
    version_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose, disable_visual_on_complete=args.disable_visual_on_complete, only_show_progress=args.only_show_progress)

def all(args):
    version_console(args)
    
def main():    
    parser = argparse.ArgumentParser(description="IDRAC module of nessus-verifier.")
    
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    
    parser_all = subparsers.add_parser("all", help="Runs all modules")
    parser_all.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_all.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_all.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_all.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_all.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_all.set_defaults(func=all)
    
    parser_version = subparsers.add_parser("smbv1", help="Checks Version")
    parser_version.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_version.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_version.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_version.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_version.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_version.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_version.set_defaults(func=version_console)