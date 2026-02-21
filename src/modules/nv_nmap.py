import subprocess
import sys
from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2
import argparse, argcomplete
import xml.etree.ElementTree as ET
import re
import ipaddress

def get_ips(filename):
    pattern = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")

    results = set()

    with open(filename, "r") as f:
        for line in f:
            for ip_str, port_str in pattern.findall(line):
                try:
                    ip = ipaddress.ip_address(ip_str)
                    port = int(port_str)

                    if 0 < port <= 65535:
                        results.add((str(ip), port))

                except ValueError:
                    pass

    return results

def command_status(args):
    hosts = get_ips(args.file)

    results = get_default_context_execution2("Nmap Status Check", args.threads, hosts, command_single)

    out = open(args.output, "w") if hasattr(args, "output") and args.output else sys.stdout

    try:
        for r in results:
            out.write(f"{r}\n")
    finally:
        if out is not sys.stdout:
            out.close()

def command_single(host, **kwargs):
    ip, port = host
    cmd = [
        "nmap",
        "-Pn",
        "-p", str(port),
        "-oX", "-",      # XML output to stdout
        ip
        ]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
        # Parse XML
    root = ET.fromstring(result.stdout)

    try:
        for p in root.findall(".//port"):
            state = p.find("state").attrib["state"] # type: ignore
            return f"{ip}:{port} => {state}"
    except Exception as e:
        pass

    return None

@error_handler(["host"])
def identify_service_single(host,**kwargs):
    ip = host.ip
    port = host.port
    exclude_ports = kwargs.get("exclude_ports", [])
    if int(port) in exclude_ports:
        return
    result = subprocess.run(
        ["nmap", "-sV", "-sT", "-p", port, "--version-all", ip],
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


def identify_service(hosts, exclude_ports, output, output2, threads, verbose = False):
    hosts = get_hosts_from_file2(hosts)

    results = get_default_context_execution2("nmap", threads, hosts, identify_service_single, verbose=verbose, exclude_ports=exclude_ports)

    v = {}

    for item in results:
        left = item["ip"] + ":" + item["port"]
        right = item["service"] + " " + item["version"]
        print(left + " => " + right)

    for item in results:
        left = item["ip"] + ":" + item["port"]
        right = item["service"] + " " + item["version"]
        if output2 and (item["service"] == "tcpwrapped" or item["service"] == "unknown" or item["service"].endswith("?")):
            if not item["service"] in v.keys():
                v[item["service"]] = []
            v[item["service"]].append(left)
            with open(output2, "a") as f:
                f.write(left + "\n")
        if output and not (item["service"] == "tcpwrapped" or item["service"] == "unknown" or item["service"].endswith("?")):
            with open(output, "a") as f:
                f.write(left + " => " + item["service"] + "\n")
            if item["service"] == "http":
                with open(f"urls.txt", "a") as f:
                    f.write("http://" + left + "\n")
            elif item["service"] == "ssl/https" or item["service"] == "ssl/http":
                with open(f"urls.txt", "a") as f:
                    f.writelines("https://" + left + "\n")
            else:
                s = item["service"].replace("/", "-")
                with open(f"{s}.txt", "a") as f:
                    f.writelines(left + "\n")
        

def command_scan(args):
    identify_service(args.file, args.exclude_ports, args.output if args.output else None, args.unknown_output if args.unknown_output else None, args.threads, verbose=True)

def parse_ports(value):
    ports = set()
    for part in value.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="Nmap module")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command 1
    p1 = subparsers.add_parser("status", help="Gets status of the ports")
    p1.add_argument("-f", "--file", required=True, help="Input file with hosts in 'ip:port' format")
    p1.add_argument("-o", "--output", required=False, help="Output file")
    p1.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    p1.set_defaults(func=command_status)

    # Command 2
    p2 = subparsers.add_parser("scan", help="Get version of the services running on the ports")
    p2.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    p2.add_argument("--exclude-ports", type=parse_ports, default="9100", nargs="+", help="Exclude ports (Default: 9100).")
    p2.add_argument("-o", "--output", type=str, default="nv-known.txt", help="Output file for knowns (Default: nv-known.txt).")
    p2.add_argument("-uo", "--unknown-output", type=str, default="nv-unknown.txt", help="Output file for unknowns (Default: nv-unknown.txt).")
    p2.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    p2.set_defaults(func=command_scan)

    args = parser.parse_args()
    argcomplete.autocomplete(parser)
    args.func(args)
    
