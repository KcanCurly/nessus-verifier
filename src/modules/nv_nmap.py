from src.utilities.utilities import get_hosts_from_file, get_classic_console
import nmap
import argparse

def identify_service(hosts, output = "", verbose = False):
    hosts = get_hosts_from_file(hosts)
    nm = nmap.PortScanner()
    
    if output:
        with open(output, "w") as f:
            for host in hosts:
                try:
                    ip = host.split(":")[0]
                    port = host.split(":")[1]
                    nm.scan(ip, port, "-sV")
                    
                    if ip in nm.all_hosts():
                        nmap_host = nm[ip]
                        print(f"{host} => {nmap_host['tcp'][int(port)]['name']}")
                        print(f"{host} => {nmap_host['tcp'][int(port)]['name']}", file=f)

                except: pass
    else:
        for host in hosts:
            try:
                ip = host.split(":")[0]
                port = host.split(":")[1]
                nm.scan(ip, port, "-sV")
                
                if ip in nm.all_hosts():
                    nmap_host = nm[ip]
                    print(f"{host} => {nmap_host['tcp'][int(port)]['name']}")

            except: pass
        
        
def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nmap scanner for nessus unknown ports.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv, -vvv, -vvvv, -vvvvvv)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")



    args = parser.parse_args()
    
    identify_service(args.file, args.output if args.output else "")