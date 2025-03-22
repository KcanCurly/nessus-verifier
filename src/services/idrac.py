from src.utilities.utilities import get_classic_overall_progress, get_classic_console, get_hosts_from_file, add_default_parser_arguments, get_default_context_execution
from rich.live import Live
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

class iDRAC_Version_Vuln_Data():
    def __init__(self, host: str, version: str):
        self.host = host
        self.version = version

def version_single(host: str, timeout = 3, errors = False, verbose = False):
    try:
        resp = requests.get(f"https://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False, timeout=timeout)
    except:
        try:
            resp = requests.get(f"http://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False, timeout=timeout)
        except Exception as e:
            if errors: print(e)
            return
    
    version = resp.json()["Attributes"]["FwVer"]
    return iDRAC_Version_Vuln_Data(host, version)


def version_nv(hosts: list[str], threads = 10, timeout = 3, errors = False, verbose = False):
    results: list[iDRAC_Version_Vuln_Data] = get_default_context_execution("iDRAC Version", threads, hosts, (version_single, timeout, errors, verbose))
    versions = {}
                
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
    version_nv(get_hosts_from_file(args.file), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("idrac")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks idrac version")
    add_default_parser_arguments(parser_version)
    parser_version.set_defaults(func=version_console)
