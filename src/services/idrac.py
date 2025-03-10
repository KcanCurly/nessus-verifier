from src.utilities.utilities import get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

class Version_Vuln_Data():
    def __init__(self, host: str, version: str):
        self.host = host
        self.version = version

def version_single(console: Console, host: str, output: str, timeout: int, verbose: bool):
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

def version_nv(l: list[str], output: str, threads: int, timeout: int, verbose: bool ):
    versions = {}
    
    overall_progress = get_classic_overall_progress()

    overall_task_id = overall_progress.add_task("", start=False, modulename="IDRAC Version")
    console = get_classic_console(force_terminal=True)
    

    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(l), completed=0)
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[Version_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                future = executor.submit(version_single, console, host, output, timeout, verbose)
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
    version_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose)

    
def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("idrac")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_all = subparsers.add_parser("version", help="Checks idrac version")
    parser_all.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_all.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_all.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_all.set_defaults(func=version_console)
