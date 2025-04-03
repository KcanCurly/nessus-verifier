from src.utilities.utilities import get_default_context_execution2, get_hosts_from_file2
import nmap
import argparse

def identify_service_single(host,**kwargs):
    nm = kwargs["nm"]
    output = kwargs["output"]
    try:
        ip = host.ip
        port = host.port
        nm.scan(ip, port, "-sV", timeout=3600)
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            print(f"{host} => {nmap_host['tcp'][int(port)]['name']}")
            return f"{host} => {nmap_host['tcp'][int(port)]['name']}"

    except: pass

def identify_service(hosts, output, threads, verbose = False):
    hosts = get_hosts_from_file2(hosts)
    nm = nmap.PortScanner()
    
    results: list[str] = get_default_context_execution2("nmap", threads, hosts, identify_service_single, nm=nm, output=output, verbose=verbose)

    result_dict = {}

    for item in results:
        left, right = item.split(" => ")  # Split string into two parts
        result_dict.setdefault(right, set()).add(left)  # Add to dictionary

    for a, b in result_dict.items():
        print(a)
        for c in b:
            print(f"  {c}")
        
        
def main():
    parser = argparse.ArgumentParser(description="Nmap scanner for nessus unknown ports.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    args = parser.parse_args()
    
    identify_service(args.file, args.output if args.output else None, args.threads)