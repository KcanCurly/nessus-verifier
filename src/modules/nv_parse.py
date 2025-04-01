import xml.etree.ElementTree as ET
import os
import argparse
import re
import yaml
from dataclasses import dataclass
import json

# Function to parse the Nessus file (.nessus format) and extract services and associated hosts
def parse_nessus_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Dictionary to store services and their associated hosts
    services = {}
    urls = set()

    # Iterate through all host elements in the XML
    for host in root.findall(".//Report/ReportHost"):
        host_ip = host.attrib['name']  # Extract the host IP

        # Iterate through all the services (plugins) for this host
        for item in host.findall(".//ReportItem"):
            service_name = item.attrib.get('svc_name', '').lower()
            port = item.attrib.get('port', '')
            
            if item.attrib.get("pluginID") == '24260' and item.attrib.get("pluginName") == "HyperText Transfer Protocol (HTTP) Information":
                # Parse the plugin output to extract SSL information

                ssl_match = re.search(r"SSL\s+:\s+(yes|no)", item.findtext('plugin_output')) # type: ignore
                if ssl_match:
                    ssl = ssl_match.group(1)
                    url = f"http{'s' if ssl == 'yes' else ''}://{host_ip}:{port}"
                    urls.add(url)
                    
            # Skip services ending with "?" (uncertain services)
            if service_name == "general":
                continue
            if service_name.endswith('?')  or service_name == "unknown":
                if "unknown" not in services:
                    services["unknown"] = set()
                services["unknown"].add(f"{host_ip}:{port}")
                continue

            # Create a directory for the service if it doesn't exist
            if service_name not in services:
                services[service_name] = set()

            # Add host IP to the service's list
            services[service_name].add(f"{host_ip}:{port}")

    return (services, urls)

# Function to create directories and save hosts in 'hosts.txt'
def save_services(services):
    output_dir = 'nv-services'

    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Iterate over the services and create directories and host files
    for service, hosts in services.items():
        service_dir = os.path.join(output_dir, service)
        if not os.path.exists(service_dir):
            os.makedirs(service_dir)
        
        # Write the hosts and ports to the 'hosts.txt' file
        with open(os.path.join(service_dir, 'hosts.txt'), 'w') as f:
            for host in hosts:
                f.write(f"{host}\n")

def save_urls(urls):
    output_file = "urls.txt"
    
    with open(output_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")
    
    
class GroupNessusScanOutput:
    def __init__(self, id, plugin_ids, hosts, sub_hosts, name):
        self.id = id
        self.name = name
        self.plugin_ids = plugin_ids
        self.hosts = hosts
        self.sub_hosts = sub_hosts
    
    def add_host(self, name, id, host) -> bool:
        if id in self.plugin_ids:
            if host not in self.hosts: self.hosts.append(host)
            if name not in self.sub_hosts:
                self.sub_hosts[name] = []
            self.sub_hosts[name].append(host)
            return True
        return False
    
    @classmethod
    def from_json(cls, data):
        return cls(**data)
    
class NessusScanOutput:
    def __init__(self, plugin_id, name, description, severity, host_port, output, cve):
        self.plugin_id = plugin_id
        self.name = name
        self.description = description
        self.severity = severity
        self.host_port = host_port
        self.output = output
        self.cve = cve

def parse_nessus_output(file_path) -> list[NessusScanOutput]:
    """
    Parses Nessus XML output and returns a list of NessusScanOutput objects.
    """
    nessus_scan_output = []
    tree = ET.parse(file_path)
    root = tree.getroot()

    for host in root.iter('ReportHost'):
        host_properties = host.find('HostProperties')
        ip_address = host_properties.findtext("./tag[@name='host-ip']") # type: ignore

        for item in host.iter('ReportItem'):
            plugin_id = int(item.get('pluginID')) # type: ignore
            name = item.get('pluginName')
            description = item.findtext('description')
            severity = item.get('severity')
            host_port = f"{ip_address}:{item.get('port')}"
            output = item.findtext('plugin_output')
            cve = item.findtext('cve')

            output = NessusScanOutput(plugin_id, name, description, severity, host_port, output, cve)
            nessus_scan_output.append(output)

    return nessus_scan_output

def read_nessus_file(filename):
    with open(filename, 'rb') as f: return f.read()
    
    
def group_up(l: list[NessusScanOutput]):
    rules: list[GroupNessusScanOutput] = []
    
    current_script_path = os.path.abspath(__file__)
    two_dirs_up = os.path.abspath(os.path.join(current_script_path, "../../"))
    rules_file_path = os.path.join(two_dirs_up, "rules.yaml")
    with open(rules_file_path, encoding='utf-8') as f:
        rule_data = yaml.safe_load(f)
        
    available_id = -1
    for rule in rule_data:
        r = GroupNessusScanOutput(rule['id'], rule['plugin-ids'], [], {}, rule['name'])
        rules.append(r)
        available_id = available_id + 1

    for n in l:
        found = False

        for rule in rules:
            if rule.add_host(n.name, n.plugin_id, n.host_port):
                found = True

        
        # No rule in rules.yaml so we make its own rule if its not on info severity
        if not found and n.severity != "0":
            new_rule = GroupNessusScanOutput(available_id, [n.plugin_id], [], {}, n.name)
            new_rule.add_host(n.name, n.plugin_id, n.host_port)
            rules.append(new_rule)
            available_id = available_id + 1

    return rules

def write_to_file(l: list[GroupNessusScanOutput], args):
    n = l
    if args.skip_ignored:
        n = l[1:]
    
    with open(args.output_file, "w") as f:
        for a in n:
            if len(a.hosts) == 0: continue
            print(a.name, file=f)
            for h in a.hosts:
                print(f"    {h}", file=f)
            # if len(a.sub_hosts.items()) == 1: continue
            print(file=f)
            for key,value in a.sub_hosts.items():
                print(f"    {key}", file=f)
                for z in value:
                    print(f"        {z}", file=f)
                    
    with open(args.output_json_file, "w") as file:
        for v in l:
            json.dump(v.__dict__, file)
            file.write("\n")


def main():
    parser = argparse.ArgumentParser(description="nessus-verifier.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a Nessus file.")
    parser.add_argument('--skip-ignored', action="store_true", help='Do not write ignored vulnerabilities to txt output.')
    parser.add_argument('-o', '--output-file', type=str, required=False, default="output.txt", help='Vulnerability Groups output file name txt (Default: output.txt).')
    parser.add_argument('-oj', '--output-json-file', type=str, required=False, default="output.ndjson", help='Vulnerability Groups output file name json (Default: output.ndjson).')
    args = parser.parse_args()

    # Parse for services and urls
    services, urls = parse_nessus_file(args.file)
    save_services(services)
    save_urls(urls)
    
    # Parse for vulnerabilities
    output = parse_nessus_output(args.file)
    rules = group_up(output)
    write_to_file(rules, args)
    
    
if __name__ == "__main__":
    main()