import subprocess
from src.utilities.utilities import get_hosts_from_file

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

def anon_nv(hosts: list[str]):
    vuln = {}
    for host in hosts:

        ip, port = host.split(":")
        for pipe in pipes:
            name, cmd = pipe.split(":")
            try:
                command = ["rpcclient", "-N", "-U", "","-c", cmd, ip]
                result = subprocess.run(command, text=True, capture_output=True)
                
                if "nt_status" not in result.stderr.lower() and "nt_status" not in result.stdout.lower(): # For some reason, errors are sometimes outted to stdout
                    if host not in vuln:
                        vuln[host] = []
                    vuln[host].append(f"{name} - {result.stdout} - {result.stderr}")
            except:pass
                
    if len(vuln) > 0:
        print("Anonymous RPC pipes detected:")
        for k,v in vuln.items():
            print(f"    {k} - {", ".join(v)}")
        
def anon_console(args):
    anon_nv(get_hosts_from_file(args.file))
        
def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("rpc")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_default = subparsers.add_parser("anonymous", help="Check if anonymous rpc calls are possible")
    parser_default.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_default.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_default.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_default.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_default.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_default.set_defaults(func=anon_console)