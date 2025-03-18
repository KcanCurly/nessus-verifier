from src.utilities.utilities import get_hosts_from_file
import argparse

def process(hosts):
    hosts = get_hosts_from_file(hosts)
    z = []
    for host in hosts:
        if "CVE-2019-9670" in host:
            z.append(host)
    if len(z) > 0:
        print("CVE-2019-9670:")
        print("msf - use exploit/linux/http/zimbra_xxe_rce")
        for a in z:
            print(a.rsplit("", 1)[1])
            
    z = []
    for host in hosts:
        if "CVE-2021-21985" in host:
            z.append(host)
    if len(z) > 0:
        print("CVE-2021-21985:")
        print("msf - use exploit/linux/http/vmware_vcenter_vsan_health_rce")
        for a in z:
            print(a.rsplit("", 1)[1])

        
        
def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Parses nuclei output and give instructions on CVEs if its known.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")

    args = parser.parse_args()
    
    process(args.file)