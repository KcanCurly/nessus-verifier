import re
import subprocess
from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2
import nmap
import argparse

@error_handler(["host"])
def identify_service_single(host,**kwargs):
    ip = host.ip
    port = host.port
    result = subprocess.run(
        ["nmap", "-sV", "-p", port, "--version-all", ip],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    pattern  = re.compile(r"^(\d+/tcp|\d+/udp)\s+open\s+(\S+)\s+(.*)$")
    match = pattern.search(result.stdout)
    if match:
        return {
            "ip": ip,
            "port": match.group(1),
            "protocol": match.group(2),
            "service": match.group(3),
            "version": match.group(4).strip()
        }


def identify_service(hosts, output, threads, verbose = False):
    hosts = get_hosts_from_file2(hosts)

    results = get_default_context_execution2("nmap", threads, hosts, identify_service_single, verbose=verbose)

    for item in results:
        left = item["ip"] + " " + item["port"]
        right = item["service"] + " " + item["version"]
        print(left + " => " + right)

    
    #with open(output, "w") as f:
    #    for a, b in result_dict.items():
    #        print(a, file=f)
    #        print("*" * 20, file=f)
    #        for c in b:
    #            print(c, file=f)
    #        print(file=f)
    #        print(file=f)
        
        
def main():
    parser = argparse.ArgumentParser(description="Nmap scanner for nessus unknown ports.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    args = parser.parse_args()
    
    identify_service(args.file, args.output if args.output else None, args.threads)