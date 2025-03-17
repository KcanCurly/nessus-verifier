import subprocess
from src.utilities.utilities import get_hosts_from_file

showmount_cmd = ["showmount", "-e", "--no-headers"]
nfsls_cmd = ["nfs-ls", "nfs://"]

def list_nv(hosts: list[str], errors = False, verbose = False):
    vuln = {}
    
    for host in hosts:
        try:
            ip, port = host.split(":")
            result = subprocess.run(showmount_cmd + [ip], text=True, capture_output=True)
            print(result.stdout)
            print(result.stderr)
            vuln[host] = []
            for line in result.stdout.splitlines():
                c = ["nfs-ls", f"nfs://{ip}{line.split()[0]}"]
                result = subprocess.run(c, text=True, capture_output=True)
                print(result.stdout)
                print(result.stderr)
                for line1 in result.stdout.splitlines():
                    vuln[host].append(line1)
                
                
        except Exception as e: 
            if errors: print(e)
    
    if len(vuln) > 0:
        print("Readable NFS List:")
        for k,v in vuln.items():
            if len(v) == 0: continue
            print(k)
            for value in v:
                print(f"    {value}")

        

def list_console(args):
    list_nv(get_hosts_from_file(args.file), args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("nfs")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_list = subparsers.add_parser("list", help="List directories of nfs shares of the hosts")
    parser_list.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_list.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_list.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_list.set_defaults(func=list_console)

