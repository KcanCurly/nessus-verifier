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

    for line in result.stdout.splitlines():
        if line.startswith(port):
            try:
                parts = line.split(maxsplit=3)
                if parts[1] == "open":
                    return {
                        "ip": ip,
                        "port": port,
                        "protocol": parts[0].split("/")[1],
                        "service": parts[2],
                        "version": parts[3]
                    }
            except:
                parts = line.split(maxsplit=2)
                if parts[1] == "open":
                    return {
                        "ip": ip,
                        "port": port,
                        "protocol": parts[0].split("/")[1],
                        "service": parts[2],
                        "version": ""
                    }


def identify_service(hosts, output, output2, threads, verbose = False):
    hosts = get_hosts_from_file2(hosts)

    results = get_default_context_execution2("nmap", threads, hosts, identify_service_single, verbose=verbose)

    for item in results:
        left = item["ip"] + " " + item["port"]
        right = item["service"] + " " + item["version"]
        print(left + " => " + right)

    for item in results:
        left = item["ip"] + ":" + item["port"]
        right = item["service"] + " " + item["version"]
        if output2 and (item["service"] == "tcpwrapped" or item["service"].endswith("?")):
            with open(output2, "a") as f:
                f.write(left + "\n")
        if output and not (item["service"] == "tcpwrapped" or item["service"].endswith("?")):
            with open(output, "a") as f:
                f.write(left + " => " + item["service"] + "\n")
        
        
def main():
    parser = argparse.ArgumentParser(description="Nmap scanner for nessus unknown ports.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    parser.add_argument("-uo", "--unkown-output", type=str, required=False, help="Output file for unknowns.")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    args = parser.parse_args()
    
    identify_service(args.file, args.output if args.output else None, args.unknown_output if args.unknown_output else None, args.threads)