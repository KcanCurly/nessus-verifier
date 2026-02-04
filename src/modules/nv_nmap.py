import subprocess
from src.utilities.utilities import error_handler, get_default_context_execution2, get_hosts_from_file2
import argparse, argcomplete

@error_handler(["host"])
def identify_service_single(host,**kwargs):
    ip = host.ip
    port = host.port
    exclude_ports = kwargs.get("exclude_ports", [])
    if int(port) in exclude_ports:
        return
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
    parser = argparse.ArgumentParser(description="Nmap scanner for nessus unknown ports.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("--exclude-ports", ttype=parse_ports, default="9100", nargs="+", help="Exclude ports (Default: 9100).")
    parser.add_argument("-o", "--output", type=str, default="nv-known.txt", help="Output file for knowns (Default: nv-known.txt).")
    parser.add_argument("-uo", "--unknown-output", type=str, default="nv-unknown.txt", help="Output file for unknowns (Default: nv-unknown.txt).")
    parser.add_argument("--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    args = parser.parse_args()
    argcomplete.autocomplete(parser)
    
    identify_service(args.file, args.exclude_ports, args.output if args.output else None, args.unknown_output if args.unknown_output else None, args.threads)