import subprocess
from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments, get_default_context_execution

class RPC_Vuln_Data():
    def __init__(self, host: str, version: list[str]):
        self.host = host
        self.version = version

pipes = [
    "LSARPC:lsaquerysecobj",
    "SAMR:querydominfo",
    "SPOOLSS:getjob",
    "SRVSVC:srvinfo",
    "DFS:dfsversion",
    "WKSSVC:wkssvc_wkstagetinfo",
    "NTSVCS:ntsvcs_getversion",
    "DRSUAPI:dsgetdcinfo",
    "EVENTLOG:eventlog_loginfo",
    "WINREG:winreg_enumkey",
    "FSRVP:fss_get_sup_version",
    ]

def anon_single(host, timeout, errors, verbose):
    vul = []
    try:
        ip, port = host.split(":")
        for pipe in pipes:
            name, cmd = pipe.split(":")
            try:
                command = ["rpcclient", "-N", "-U", "","-c", cmd, ip]
                result = subprocess.run(command, text=True, capture_output=True)
                
                if "nt_status" not in result.stderr.lower() and "nt_status" not in result.stdout.lower(): # For some reason, errors are sometimes outted to stdout
                    vul.append(f"{name} - {result.stdout} - {result.stderr}")
            except:pass
    except Exception as e:
        if errors: print(f"Error for host {host}: {e}")
    if len(vul) > 0:
        return RPC_Vuln_Data(host, vul) 

def anon_nv(hosts, threads, timeout, errors, verbose):
    results: list[RPC_Vuln_Data] = get_default_context_execution("RPC Anonymous Access Check", threads, hosts, (anon_single, timeout, errors, verbose))
    
    if len(results):
        print("Anonymous RPC pipes detected:")
        for r in results:
            print(r.host)
            for value in r.version:
                print(f"    {value}")
        
def anon_console(args):
    anon_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)
        
def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("rpc")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_anon = subparsers.add_parser("anonymous", help="Check if anonymous rpc calls are possible")
    add_default_parser_arguments(parser_anon)
    parser_anon.set_defaults(func=anon_console)