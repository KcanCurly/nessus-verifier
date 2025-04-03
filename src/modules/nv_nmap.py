from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2
import nmap
import argparse

@error_handler(["host"])
def identify_service_single(host,**kwargs):
    nm = kwargs["nm"]

    ip = host.ip
    port = host.port
    nm.scan(ip, port, "-sV", timeout=3600)
    if ip in nm.all_hosts():
        nmap_host = nm[ip]
        srv = nmap_host['tcp'][int(port)]['name']
        if srv:
            print(f"{host} => {srv}")
            return f"{host} => {srv}"

def identify_service(hosts, output, threads, verbose = False):
    hosts = get_hosts_from_file2(hosts)
    nm = nmap.PortScanner()
    
    results: list[str] = get_default_context_execution2("nmap", threads, hosts, identify_service_single, nm=nm, verbose=verbose)

    result_dict = {}

    for item in results:
        left, right = item.split(" => ")  # Split string into two parts
        result_dict.setdefault(right, []).append(left)  # Add to dictionary

    with open(output, "w") as f:
        for a, b in result_dict.items():
            print(a, file=f)
            print("*" * 20, file=f)
            for c in b:
                print(c, file=f)
            print(file=f)
            print(file=f)
        
        
def main():
    parser = argparse.ArgumentParser(description="Nmap scanner for nessus unknown ports.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    args = parser.parse_args()
    
    identify_service(args.file, args.output if args.output else None, args.threads)