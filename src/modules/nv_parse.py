from ast import parse
import xml.etree.ElementTree as ET
import os
import argparse, argcomplete
import re
import yaml
import json
import cidr_man

sitemap_shortcut = {}

nessus_xml_tree = None

def read_nessus_file(filename):
    global nessus_xml_tree
    nessus_xml_tree = ET.parse(filename)
    return nessus_xml_tree

# Function to parse the Nessus file (.nessus format) and extract services and associated hosts
def parse_nessus_file(tree, include = None, exclude = None):
    global sitemap_shortcut
    root = tree.getroot()

    # Dictionary to store services and their associated hosts
    services = {}
    urls = set()

    # Iterate through all host elements in the XML
    for host in root.findall(".//Report/ReportHost"):
        host_ip = host.attrib['name']  # Extract the host IP

        if include:
            if not any(cidr_man.CIDR(host_ip) in net for net in include):
                continue

        if exclude:
            if any(cidr_man.CIDR(host_ip) in net for net in exclude):
                continue

        # Iterate through all the services (plugins) for this host
        for item in host.findall(".//ReportItem"):
            service_name = item.attrib.get('svc_name', '').lower()
            port = item.attrib.get('port', 0)
            if not port: # Skip port 0
                continue

            if item.attrib.get("pluginName") == "Web Application Sitemap":
                sitemap_shortcut[f"{host_ip}:{port}"] = item.findtext('plugin_output')

            
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
        # Protocol specific things
        if service == "cifs":
            with open(os.path.join(service_dir, 'ips.txt'), 'w') as f:
                for host in hosts:
                    f.write(f"{host.split(":")[0]}\n")

def get_plugin_output(pluginName, ip_port):
    ip, port = ip_port.split(":")
    root = nessus_xml_tree.getroot() # type: ignore
    for host in root.findall(".//Report/ReportHost"):
        host_ip = host.attrib['name']  # Extract the host IP
        if ip == host_ip:
            for report_item in host.findall(".//ReportItem"):
                if report_item.attrib.get("pluginName") == pluginName and report_item.attrib.get('port', 0) == port:
                    return report_item.findtext('plugin_output')


def save_urls(urls):
    output_file = "urls.txt"
    
    with open(output_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")
    
    
class GroupNessusScanOutput:
    def __init__(self, id, plugin_ids, should_group_total, hosts, sub_hosts, name, regexes):
        self.id = id
        self.name = name
        self.plugin_ids = plugin_ids
        self.should_group_total = should_group_total
        self.hosts = hosts
        self.sub_hosts = sub_hosts
        self.regexes = regexes
    
    def check_and_add_host(self, name, id, host) -> bool:
        if id in self.plugin_ids:
            if host not in self.hosts: self.hosts.append(host)
            if name not in self.sub_hosts:
                self.sub_hosts[name] = []
            self.sub_hosts[name].append(host)
            return True
        elif self.regexes:
            for r in self.regexes:
                if re.search(r, name):
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

def parse_nessus_output(tree) -> list[NessusScanOutput]:
    """
    Parses Nessus XML output and returns a list of NessusScanOutput objects.
    """
    nessus_scan_output = []
    root = tree.getroot()

    for host in root.iter('ReportHost'):
        host_properties = host.find('HostProperties')
        ip_address = host_properties.findtext("./tag[@name='host-ip']") # type: ignore

        for item in host.iter('ReportItem'):
            if item.get('port') == '0':
                continue

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
    
def group_up(l: list[NessusScanOutput], parse_severity0: bool) -> list[GroupNessusScanOutput]:
    rules: list[GroupNessusScanOutput] = []
    
    current_script_path = os.path.abspath(__file__)
    two_dirs_up = os.path.abspath(os.path.join(current_script_path, "../../"))
    rules_file_path = os.path.join(two_dirs_up, "rules.yaml")
    with open(rules_file_path, encoding='utf-8') as f:
        rule_data = yaml.safe_load(f)
        
    available_id = -1
    for rule in rule_data:
        r = GroupNessusScanOutput(rule['id'], rule['plugin-ids'], rule['should-group-total'], [], {}, rule['name'], rule['plugin-regex'])
        rules.append(r)
        available_id = available_id + 1

    for n in l:
        found = False

        for rule in rules:
            if rule.check_and_add_host(n.name, n.plugin_id, n.host_port):
                found = True

        
        # No rule in rules.yaml so we make its own rule if its not on info severity
        if not found:
            if not parse_severity0 and n.severity == "0":
                continue
            new_rule = GroupNessusScanOutput(available_id, [n.plugin_id], False, [], {}, n.name, [])
            new_rule.check_and_add_host(n.name, n.plugin_id, n.host_port)
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
            if a.should_group_total:
                for h in a.hosts:
                    print(f"    {h}", file=f)

            if a.should_group_total:
                print(file=f)
            for key,value in a.sub_hosts.items():
                print(f"    {key}", file=f)
                for z in value:
                    print(f"        {z}", file=f)
                    if key == "Browsable Web Directories":
                        plugin_output = get_plugin_output("Browsable Web Directories", z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[6:]:
                            print(f"            {p}", file=f)
                    elif key == "SQL Dump Files Disclosed via Web Server":
                        plugin_output = get_plugin_output("SQL Dump Files Disclosed via Web Server", z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[12:]:
                            print(f"            {p}", file=f)
                    elif key == "CVS (Web-Based) Entries File Information Disclosure":
                        plugin_output = get_plugin_output("CVS (Web-Based) Entries File Information Disclosure", z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[14:]:
                            print(f"            {p}", file=f)
                    elif key == "PHP expose_php Information Disclosure":
                        plugin_output = get_plugin_output("PHP expose_php Information Disclosure", z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[12:]:
                            print(f"            {p}", file=f)
                    elif key == "Web Application Sitemap":
                        plugin_output = sitemap_shortcut[z]
                        urls =re.findall(r"https?://\S+", plugin_output) # type: ignore
                        for p in urls:
                            print(f"            {p}", file=f)
                    elif key == "Web Server Directory Enumeration":
                        plugin_output = get_plugin_output("Web Server Directory Enumeration", z)
                        urls =re.findall(r"/\S+", plugin_output) # type: ignore
                        if "disc" in plugin_output: # type: ignore
                            print(f"            [NO AUTH]", file=f)
                        else:
                            print(f"            [AUTH]", file=f)
                        for p in urls:
                            print(f"            {p}", file=f)
                    elif key == "Web Server Harvested Email Addresses":
                        plugin_output = get_plugin_output("Web Server Harvested Email Addresses", z)
                        plugin_output_s = plugin_output.split("- ") # type: ignore
                        z = plugin_output_s[1].strip().split()
                        for p in z:
                            if p == "referenced" or p == "from" or p == ":":
                                continue
                            if "@" in p:
                                p = p.replace('\'', "")
                                p = p.replace(',', ":")
                            elif "/" in p:
                                p = p.replace('/', "    /")
                            print(f"            {p}", file=f)
                    elif key == "Web mirroring":
                        plugin_output = get_plugin_output("Web mirroring", z)
                        plugin_output_s = plugin_output.split("+ CGI : ") # type: ignore
                        for p in plugin_output_s[1:]:
                                print(f"            {p.split()}", file=f)
                    elif key == "Web Server Office File Inventory":
                        plugin_output = get_plugin_output("Web Server Office File Inventory", z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        r = plugin_output_s[12:]
                        r.reverse()
                        for p in r:
                            if p == ":":
                                break
                            print(f"            {p}", file=f)
                    elif key == "Web Server robots.txt Information Disclosure":
                        plugin_output = get_plugin_output("Web Server robots.txt Information Disclosure", z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        print(f"            {plugin_output_s}", file=f)
                    elif key == "Backup Files Disclosure":
                        plugin_output = get_plugin_output("Backup Files Disclosure", z)
                        urls =re.findall(r"https?://\S+", plugin_output) # type: ignore
                        for p in urls:
                            print(f"            {p}", file=f)
                    elif key == "LDAP User Enumeration":
                        plugin_output = get_plugin_output("LDAP User Enumeration", z)
                        sections = plugin_output.split("|") # type: ignore
                        for s in sections:
                            print(f"            {s}", file=f)
                    elif key == "Multiple Mail Server EXPN/VRFY Information Disclosure":
                        plugin_output = get_plugin_output("Multiple Mail Server EXPN/VRFY Information Disclosure", z)
                        lines = plugin_output.splitlines() # type: ignore
                        for la in lines:
                            la = la.strip()
                            if not (la.startswith("Here") or la == ""):
                                print(f"            {la}", file=f)
                    elif key == "Apache Multiviews Arbitrary Directory Listing":
                        pattern = r"https?://.*"
                        plugin_output = get_plugin_output("Apache Multiviews Arbitrary Directory Listing", z)
                        match = re.search(pattern, plugin_output) # type: ignore
                        if match:
                            print(f"            {match.group()}", file=f)
                    elif key == "SMB Use Host SID to Enumerate Local Users Without Credentials":
                        pattern = r"- .*"
                        plugin_output = get_plugin_output("SMB Use Host SID to Enumerate Local Users Without Credentials", z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "SMB Use Domain SID to Enumerate Users":
                        pattern = r"- .*"
                        plugin_output = get_plugin_output("SMB Use Domain SID to Enumerate Users", z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "DNS Server Zone Transfer Information Disclosure (AXFR)":
                        plugin_output = get_plugin_output("DNS Server Zone Transfer Information Disclosure (AXFR)", z)
                        for m in plugin_output.splitlines(): # type: ignore
                            print(f"            {m}", file=f)
                    elif key == "LDAP &apos;Domain Admins&apos; Group Membership Enumeration":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("LDAP &apos;Domain Admins&apos; Group Membership Enumeration", z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "LDAP 'Domain Admins' Group Membership Enumeration":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("LDAP 'Domain Admins' Group Membership Enumeration", z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "LDAP Group Enumeration":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("LDAP Group Enumeration", z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "SNMP Request Cisco Router Information Disclosure":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("SNMP Request Cisco Router Information Disclosure", z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            print(f"            {m.strip()}", file=f)
                    elif key == "SNMP Query System Information Disclosure":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("SNMP Query System Information Disclosure", z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            print(f"            {m.strip()}", file=f)
                    elif key == "SNMP Request Network Interfaces Enumeration":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("SNMP Request Network Interfaces Enumeration", z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            print(f"            {m.strip()}", file=f)
                    elif key == "SNMP Query Installed Software Disclosure":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("SNMP Query Installed Software Disclosure", z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            print(f"            {m.strip()}", file=f)
                    elif key == "SNMP Query Running Process List Disclosure":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("SNMP Query Running Process List Disclosure", z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            print(f"            {m.strip()}", file=f)
                    elif key == "SNMP Query Routing Information Disclosure":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output("SNMP Query Routing Information Disclosure", z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            print(f"            {m.strip()}", file=f)


    with open(args.output_json_file, "w") as file:
        for v in l:
            json.dump(v.__dict__, file)
            file.write("\n")


def main():
    parser = argparse.ArgumentParser(description="nessus-verifier.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a Nessus file.")
    parser.add_argument('--severity0', action="store_true", help='Parse serverity 0 findings.')
    parser.add_argument('--skip-ignored', action="store_true", help='Do not write ignored vulnerabilities to txt output.')
    parser.add_argument('-o', '--output-file', type=str, required=False, default="output.txt", help='Vulnerability Groups output file name txt (Default: output.txt).')
    parser.add_argument('-oj', '--output-json-file', type=str, required=False, default="output.ndjson", help='Vulnerability Groups output file name json (Default: output.ndjson).')
    parser.add_argument('--include-list', type=str, required=False, help='Only process IPs that is in the given file.')
    parser.add_argument('--exclude-list', type=str, required=False, help='Only process IPs that is NOT in the given file.')
    args = parser.parse_args()
    argcomplete.autocomplete(parser)

    include = None
    exclude = None

    if args.include_list:
        with open(args.include_list, "r") as f:
            include = [cidr_man.CIDR(i) for i in f]

    if args.exclude_list:
        with open(args.exclude_list, "r") as f:
            exclude = [cidr_man.CIDR(i) for i in f]

    tree = read_nessus_file(args.file)

    # Parse for services and urls
    services, urls = parse_nessus_file(tree, include, exclude)
    save_services(services)
    save_urls(urls)
    
    # Parse for vulnerabilities
    output = parse_nessus_output(tree)
    rules = group_up(output, args.severity0)
    write_to_file(rules, args)
