from src.utilities.utilities import get_classic_overall_progress, get_classic_console, get_hosts_from_file, add_default_parser_arguments, get_default_context_execution
from rich.live import Live
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

class iDRAC_Version_Vuln_Data():
    def __init__(self, host: str, main_version:str, version: str):
        self.host = host
        self.main_version = main_version
        self.version = version

def version_single(host: str, timeout = 3, errors = False, verbose = False):
    try:
        resp = requests.get(f"https://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False, timeout=timeout)
        version = resp.json()["Attributes"]["FwVer"]
        return iDRAC_Version_Vuln_Data(host, "9", version)
    except:
        try:
            resp = requests.get(f"http://{host}/sysmgmt/2015/bmc/info", allow_redirects=True, verify=False, timeout=timeout)
            version = resp.json()["Attributes"]["FwVer"]
            return iDRAC_Version_Vuln_Data(host, "9", version)
        except Exception as e:
            if errors: print(f"Not idrac 9: {host}")
    try:
        resp = requests.get(f"https://{host}/session?aimGetProp=fwVersion", allow_redirects=True, verify=False, timeout=timeout)
        version = resp.json()["aimGetProp"]["fwVersion"]
        return iDRAC_Version_Vuln_Data(host, "7", version)
    except:
        try:
            resp = requests.get(f"http://{host}/session?aimGetProp=fwVersion", allow_redirects=True, verify=False, timeout=timeout)
            version = resp.json()["aimGetProp"]["fwVersion"]
            return iDRAC_Version_Vuln_Data(host, "7", version)
        except Exception as e:
            if errors: print(f"Not idrac 7: {host}")


def version_nv(hosts: list[str], threads = 10, timeout = 3, errors = False, verbose = False):
    results: list[iDRAC_Version_Vuln_Data] = get_default_context_execution("iDRAC Version", threads, hosts, (version_single, timeout, errors, verbose))
    versions_9 = {}
    versions_7 = {}
                
    for r in results:
        if not r: continue
        if r.main_version == "9":
            if r.version not in versions_9:
                versions_9[r.version] = set()
            versions_9[r.version].add(r.host)
        if r.main_version == "7":
            if r.version not in versions_7:
                versions_7[r.version] = set()
            versions_7[r.version].add(r.host)

    if len(versions_9) > 0:
        print("Detected iDRAC 9 versions:")
        for key, value in versions_9.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
                
    if len(versions_7) > 0:
        print("Detected iDRAC 7 versions:")
        for key, value in versions_7.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")

def version_console(args):
    version_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("idrac")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks idrac version")
    add_default_parser_arguments(parser_version)
    parser_version.set_defaults(func=version_console)
