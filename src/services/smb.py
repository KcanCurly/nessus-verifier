import argparse
import configparser
import os
from pathlib import Path
import subprocess
import re
from impacket.smbconnection import SMBConnection
from src.utilities.utilities import get_hosts_from_file
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.services.service import Vuln_Data
from rich.console import Group
from rich.panel import Panel

class SMBV1_Vuln_Data(Vuln_Data):
    def __init__(self, host: str, is_vuln: bool):
        self.host = host
        self.is_vuln = is_vuln
        
class Sign_Vuln_Data(Vuln_Data):
    def __init__(self, host: str, is_vuln: bool):
        self.host = host
        self.is_vuln = is_vuln
        
class NullGuest_Vuln_Data(Vuln_Data):
    def __init__(self, host: str, null_files: dict[str, list[str]], guest_files: dict[str, list[str]]):
        self.host = host
        self.null_files = null_files
        self.guest_files = guest_files

def nullguest_single(single_progress: Progress, single_task_id: TaskID, console: Console, host: str, output: str, timeout: int, verbose: bool):
    null_vuln = {}
    guest_vuln = {}
    
    ip = host.split(":")[0]
    port = host.split(":")[1]
    
    single_progress.update(single_task_id, status = "Running")
    
    # Get NetBIOS of the remote computer
    command = ["nmblookup", "-A", ip]
    result = subprocess.run(command, text=True, capture_output=True)
    netbios_re = r"\s+(.*)\s+<20>"
    
    s = re.search(netbios_re, result.stdout)
    if s:
        nbname = s.group()
    
        try:
            conn = pysmbconn.SMBConnection('', '', '', nbname, is_direct_tcp=True)
            if not conn.connect(ip, int(port), timeout=timeout): 
                single_progress.update(single_task_id, status = "[red]SMB connect failed[/red]",advance=1)
            else:

                shares = conn.listShares(timeout=timeout)

                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        
                        null_vuln[share.name] = []

                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            null_vuln[share.name].append(file.filename)
                    except Exception: pass

                single_progress.update(single_task_id, status = "[green]Process finished[/green]",advance=1)
        except Exception as e:
                single_progress.update(single_task_id, status = f"[red]Failed {e}[/red]",advance=1)
        try:
            conn = pysmbconn.SMBConnection('guest', '', '', nbname, is_direct_tcp=True)
            if not conn.connect(ip, int(port), timeout=timeout): 
                single_progress.update(single_task_id, status = "[red]SMB connect failed[/red]",advance=1)
            else:
                
                shares = conn.listShares(timeout=timeout)

                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        
                        guest_vuln[share.name] = []

                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            guest_vuln[share.name].append(file.filename)
                    except Exception: pass
                single_progress.update(single_task_id, status = "[green]Process finished[/green]",advance=1)
                    
        except Exception as e:
                single_progress.update(single_task_id, status = f"[red]Failed {e}[/red]",advance=1)
            
    return NullGuest_Vuln_Data(host, null_vuln, guest_vuln)

def nullguest_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    null_vuln: dict[str, dict[str, list[str]]] = {}
    guest_vuln: dict[str, dict[str, list[str]]] = {}
    
    overall_progress = get_classic_overall_progress()
    single_progress = get_classic_single_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="Null/Guest Share Check")
    console = get_classic_console(force_terminal=True)
    progress_group = Group(
        Panel(single_progress, title="Null/Guest Share Check", expand=False),
        overall_progress,
    )
    
    with Live(progress_group, console=console):
        overall_progress.update(overall_task_id, total=len(l), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[NullGuest_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                single_task_id = single_progress.add_task("single", start=False, host=host, status="status", total=1)
                future = executor.submit(nullguest_single, single_progress, single_task_id, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                overall_progress.update(overall_task_id, advance=1)
                results.append(a.result())
    for r in results:
        if not r: continue
        null_vuln[r.host] = {}
        for share, files in r.null_files.items():
            null_vuln[r.host][share] = files
        for share, files in r.guest_files.items():
            guest_vuln[r.host][share] = files
    
    if len(null_vuln) > 0:
        print("Null Accessble Shares Found:")
        for host, info in null_vuln.items():
            print(f"{host}:")
            for share, files in info.items():
                print(f"    {share}:")
                for file in files:
                    print(f"        {file}")

    if len(guest_vuln) > 0:
        print("Guest Accessble Shares Found:")
        for host, info in guest_vuln.items():
            print(f"{host}:")
            for share, files in info.items():
                print(f"    {share}:")
                for file in files:
                    print(f"        {file}")


def nullguest_console(args):
    nullguest_nv(get_hosts_from_file(args.file))

def sign_single(single_progress: Progress, single_task_id: TaskID, console: Console, host: str, output: str, timeout: int, verbose: bool):
    ip = host.split(":")[0]
    port = host.split(":")[1]
    single_progress.update(single_task_id, status = "Running")
    try:
        conn = SMBConnection(ip, ip, sess_port=int(port), timeout=timeout)
        if not conn._SMBConnection.is_signing_required(): 
            single_progress.update(single_task_id, status="[red]Signing NOT enabled[/red]", advance=1)
            return Sign_Vuln_Data(host, True)
        else:
            single_progress.update(single_task_id, status="[green]Signing is enabled[/green]", advance=1)
            return Sign_Vuln_Data(host, False)
    except Exception as e: 
        single_progress.update(single_task_id, status=f"[red]Failed: {e}[/red]", advance=1)
    return Sign_Vuln_Data(host, False)

def sign_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    vuln = []
    
    overall_progress = get_classic_overall_progress()
    single_progress = get_classic_single_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SMB Signing Check")
    console = get_classic_console(force_terminal=True)
    progress_group = Group(
        Panel(single_progress, title="SMB Signing Check", expand=False),
        overall_progress,
    )
    
    with Live(progress_group, console=console):
        overall_progress.update(overall_task_id, total=len(l), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[Sign_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                single_task_id = single_progress.add_task("single", start=False, host=host, status="status", total=1)
                future = executor.submit(sign_single, single_progress, single_task_id, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                overall_progress.update(overall_task_id, advance=1)
                results.append(a.result())
    for r in results:
        if not r: continue
        if r.is_vuln: vuln.append(r.host)

    if len(vuln) > 0:
        print("SMB signing NOT enabled on hosts:")
        for v in vuln:
            print(f"\t{v}")

def sign_console(args):
    sign_nv(get_hosts_from_file(args.file))      

def smbv1_single(single_progress: Progress, single_task_id: TaskID, console: Console, host: str, output: str, timeout: int, verbose: bool):
    ip = host.split(":")[0]
    port = host.split(":")[1]
    single_progress.update(single_task_id, status = "Running")
    try:
        SMBConnection(ip, ip, sess_port=int(port), timeout=timeout, preferredDialect="NT LM 0.12")
        single_progress.update(single_task_id, status=f"[red]SMBv1[/red]", advance=1)
        return SMBV1_Vuln_Data(host, True)
    except Exception as e: single_progress.update(single_task_id, status=f"[red]Failed: {e}[/red]", advance=1)
    return SMBV1_Vuln_Data(host, False)

def smbv1_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    vuln = []
    
    overall_progress = get_classic_overall_progress()
    single_progress = get_classic_single_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SMBv1 Check")
    console = get_classic_console(force_terminal=True)
    progress_group = Group(
        Panel(single_progress, title="SMBv1 Check", expand=False),
        overall_progress,
    )
    
    with Live(progress_group, console=console):
        overall_progress.update(overall_task_id, total=len(l), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[SMBV1_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                single_task_id = single_progress.add_task("single", start=False, host=host, status="status", total=1)
                future = executor.submit(smbv1_single, single_progress, single_task_id, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                overall_progress.update(overall_task_id, advance=1)
                results.append(a.result())
    for r in results:
        if not r: continue
        if r.is_vuln: vuln.append(r.host)

    if len(vuln) > 0:
        print("SMBv1 enabled on hosts:")
        for v in vuln:
            print(f"\t{v}")

def smbv1_console(args):
    smbv1_nv(get_hosts_from_file(args.file))

def all(args):
    smbv1_console(args)
    sign_console(args)
    nullguest_console(args)

def main():
    parser = argparse.ArgumentParser(description="SMB module of nessus-verifier.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    
    parser_smbv1 = subparsers.add_parser("all", help="Runs all modules")
    parser_smbv1.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_smbv1.set_defaults(func=all)
    
    parser_smbv1 = subparsers.add_parser("smbv1", help="Checks SMBv1 usage")
    parser_smbv1.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_smbv1.set_defaults(func=smbv1_console)
    
    parser_sign = subparsers.add_parser("sign", help="Checks SMB Signing")
    parser_sign.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_sign.set_defaults(func=sign_console)
    
    parser_sign = subparsers.add_parser("nullguest", help="Checks Null/Guest Share Access")
    parser_sign.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_sign.set_defaults(func=nullguest_console)

    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()