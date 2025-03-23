import subprocess
from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments

class NFS_Vuln_Data():
    def __init__(self, host: str, content: dict[str, list[str]]):
        self.host = host
        self.content = content

showmount_cmd = ["showmount", "-e", "--no-headers"]
nfsls_cmd = ["nfs-ls", "nfs://"]

def list_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        result = subprocess.run(showmount_cmd + [ip], text=True, capture_output=True)
        v = NFS_Vuln_Data(host, dict[str, list[str]]())
        for line in result.stdout.splitlines():
            c = ["nfs-ls", f"nfs://{ip}{line.split()[0]}"]
            result = subprocess.run(c, text=True, capture_output=True)
            v.content[line.split()[0]] = []
            for line1 in result.stdout.splitlines():
                v.content[line.split()[0]].append(line1.rsplit(" ", 1)[1])
                
        if len(v.content.keys) > 0: return v
            
            
    except Exception as e: 
        if errors: print(f"Error for {host}: {e}")
    

def list_nv(hosts, threads, timeout, errors, verbose):
    results: list[NFS_Vuln_Data] = get_default_context_execution("NFS List", threads, hosts, (list_single, timeout, errors, verbose))

    if len(results) > 0:
        print("Readable NFS List:")
        for r in results:
            print(r)
            for k,v in r.content:
                print(f"    {k}:")
                for n in v:
                    print(f"        {n}")
        

def list_console(args):
    list_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("nfs")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_list = subparsers.add_parser("list", help="List directories of nfs shares of the hosts")
    add_default_parser_arguments(parser_list)
    parser_list.set_defaults(func=list_console)

