import subprocess
import re
from impacket.smbconnection import SMBConnection
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
class SMBV1_Vuln_Data():
    def __init__(self, host: str, is_vuln: bool):
        self.host = host
        self.is_vuln = is_vuln
        
class Sign_Vuln_Data():
    def __init__(self, host: str, is_vuln: bool):
        self.host = host
        self.is_vuln = is_vuln
        
class NullGuest_Vuln_Data():
    def __init__(self, host: str, null_files: dict[str, list[str]], guest_files: dict[str, list[str]]):
        self.host = host
        self.null_files = null_files
        self.guest_files = guest_files

def nullguest_single(console: Console, host: str, output: str, timeout: int, verbose: bool):
    null_vuln = {}
    guest_vuln = {}
    
    ip, port = host.split(":")

    # Get NetBIOS of the remote computer
    command = ["nmblookup", "-A", ip]
    result = subprocess.run(command, text=True, capture_output=True, timeout=15)
    netbios_re = r"\s+(.*)\s+<20>"
    
    s = re.search(netbios_re, result.stdout)
    if s:
        nbname = s.group()
        try:
            conn = pysmbconn.SMBConnection('', '', '', nbname, is_direct_tcp=True)
            if not conn.connect(ip, 445): pass
            else:
                shares = conn.listShares()
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        null_vuln[share.name] = []

                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            null_vuln[share.name].append(file.filename)
                    except Exception: pass

        except Exception as e:
                pass
        try:
            conn = pysmbconn.SMBConnection('guest', '', '', nbname, is_direct_tcp=True)
            if not conn.connect(ip, 445): 
                pass
            else:
                shares = conn.listShares()
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        guest_vuln[share.name] = []
                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            guest_vuln[share.name].append(file.filename)
                    except Exception: pass
        except Exception as e:
                pass
    return NullGuest_Vuln_Data(host, null_vuln, guest_vuln)

def nullguest_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False, only_show_progress: bool = False):
    null_vuln: dict[str, dict[str, list[str]]] = {}
    guest_vuln: dict[str, dict[str, list[str]]] = {}
    
    overall_progress = get_classic_overall_progress()

    overall_task_id = overall_progress.add_task("", start=False, modulename="Null/Guest Share Check")
    console = get_classic_console(force_terminal=True)

    
    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(hosts), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[NullGuest_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in hosts:
                future = executor.submit(nullguest_single, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                overall_progress.update(overall_task_id, advance=1)
                results.append(a.result())
    for r in results:
        if not r: continue
        null_vuln[r.host] = {}
        guest_vuln[r.host] = {}
        for share, files in r.null_files.items():
            null_vuln[r.host][share] = files
        for share, files in r.guest_files.items():
            guest_vuln[r.host][share] = files
    
    if len(null_vuln) > 0:
        print("Null Accessble Shares Found:")
        for host, info in null_vuln.items():
            if len(info.items()) <= 0: continue
            print(f"{host}:")
            for share, files in info.items():
                print(f"    {share}:")
                for file in files:
                    print(f"        {file}")

    if len(guest_vuln) > 0:
        print("Guest Accessble Shares Found:")
        for host, info in guest_vuln.items():
            if len(info.items()) <= 0: continue
            print(f"{host}:")
            for share, files in info.items():
                print(f"    {share}:")
                for file in files:
                    print(f"        {file}")


def nullguest_console(args):
    nullguest_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose)

def sign_single(console: Console, host: str, output: str, timeout: int, verbose: bool):
    ip = host.split(":")[0]
    port = host.split(":")[1]

    try:
        conn = SMBConnection(ip, ip, sess_port=int(port), timeout=timeout)
        if not conn._SMBConnection.is_signing_required(): 
            return Sign_Vuln_Data(host, True)
        else:
            return Sign_Vuln_Data(host, False)
    except Exception as e: pass
    return Sign_Vuln_Data(host, False)

def sign_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    vuln = []
    
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SMB Signing Check")
    console = get_classic_console(force_terminal=True)
    
    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(hosts), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[Sign_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in hosts:
                future = executor.submit(sign_single, console, host, output, timeout, verbose)
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
            print(f"    {v}")

def sign_console(args):
    sign_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose, disable_visual_on_complete=args.disable_visual_on_complete)      

def smbv1_single(console: Console, host: str, output: str, timeout: int, verbose: bool):
    ip = host.split(":")[0]
    port = host.split(":")[1]
    try:
        SMBConnection(ip, ip, sess_port=int(port), timeout=timeout, preferredDialect="NT LM 0.12")
        return SMBV1_Vuln_Data(host, True)
    except Exception as e: pass
    return SMBV1_Vuln_Data(host, False)

def smbv1_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    vuln = []
    
    overall_progress = get_classic_overall_progress()
    overall_task_id = overall_progress.add_task("", start=False, modulename="SMBv1 Check")
    console = get_classic_console(force_terminal=True)

    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(hosts), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[SMBV1_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in hosts:
                future = executor.submit(smbv1_single, console, host, output, timeout, verbose)
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
            print(f"    {v}")

def smbv1_console(args):
    smbv1_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose, disable_visual_on_complete=args.disable_visual_on_complete)


def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("smb")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_smbv1 = subparsers.add_parser("smbv1", help="Checks SMBv1 usage")
    parser_smbv1.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_smbv1.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_smbv1.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_smbv1.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_smbv1.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_smbv1.set_defaults(func=smbv1_console)
    
    parser_sign = subparsers.add_parser("sign", help="Checks SMB Signing")
    parser_sign.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_sign.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_sign.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_sign.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_sign.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_sign.set_defaults(func=sign_console)
    
    parser_nullguest = subparsers.add_parser("nullguest", help="Checks Null/Guest Share Access")
    parser_nullguest.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_nullguest.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_nullguest.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_nullguest.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_nullguest.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_nullguest.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_nullguest.set_defaults(func=nullguest_console)