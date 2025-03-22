from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments, get_default_context_execution, get_url_response
import requests

class iDRAC_Version_Vuln_Data():
    def __init__(self, host: str, main_version:str, version: str):
        self.host = host
        self.main_version = main_version
        self.version = version

def version_single(host: str, timeout = 3, errors = False, verbose = False):
    try:
        resp = get_url_response(f"{host}/sysmgmt/2015/bmc/info", timeout, False)
        print(f"{host} - {resp.status_code}")
        if resp.status_code >= 400:
            print("ZZ")
            resp = get_url_response(f"{host}/session?aimGetProp=fwVersion", timeout, False)
            print(resp.text)
            if resp.status_code not in [200]: return
            print(resp.text)
            version = resp.json()["aimGetProp"]["fwVersion"]
            resp = get_url_response(f"{host}/login.html", timeout, False)
            if "iDRAC7" in resp.text: return iDRAC_Version_Vuln_Data(host, "7", version)
            elif "iDRAC8" in resp.text: return iDRAC_Version_Vuln_Data(host, "8", version)
            else: return iDRAC_Version_Vuln_Data(host, "N/A", version)
        version = resp.json()["Attributes"]["FwVer"]
        return iDRAC_Version_Vuln_Data(host, "9", version)
    except Exception as e:
        if errors: print(f"Error for {host} - {e}")

def version_nv(hosts: list[str], threads = 10, timeout = 3, errors = False, verbose = False):
    results: list[iDRAC_Version_Vuln_Data] = get_default_context_execution("iDRAC Version", threads, hosts, (version_single, timeout, errors, verbose))
    versions_9 = {}
    versions_8 = {}
    versions_7 = {}
    versions_unknown = {}
                
    for r in results:
        if not r: continue
        if r.main_version == "9":
            if r.version not in versions_9:
                versions_9[r.version] = set()
            versions_9[r.version].add(r.host)
        elif r.main_version == "8":
            if r.version not in versions_8:
                versions_8[r.version] = set()
            versions_8[r.version].add(r.host)
        elif r.main_version == "7":
            if r.version not in versions_7:
                versions_7[r.version] = set()
            versions_7[r.version].add(r.host)
        else:
            if r.version not in versions_unknown:
                versions_unknown[r.version] = set()
            versions_unknown[r.version].add(r.host)

    if len(versions_9) > 0:
        print("Detected iDRAC 9 versions:")
        for key, value in versions_9.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
                
    if len(versions_8) > 0:
        print("Detected iDRAC 8 versions:")
        for key, value in versions_8.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
                
    if len(versions_7) > 0:
        print("Detected iDRAC 7 versions:")
        for key, value in versions_7.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")
                
    if len(versions_unknown) > 0:
        print("Detected iDRAC versions:")
        for key, value in versions_unknown.items():
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
