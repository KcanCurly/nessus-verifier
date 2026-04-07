import xml.etree.ElementTree as ET
import os
import argparse, argcomplete
import re
import yaml
import json
import cidr_man
from src.modules.parse_post.post_http_server import get_instances as get_http_server_instances

sitemap_shortcut = {}
plugin_shortcut = {}
plugin_output_splitlines = [
    "Web Server robots.txt Information Disclosure",
    "MySQL Protocol Remote User Enumeration",
    "Web Application Information Disclosure",
    "Web Application Potentially Sensitive CGI Parameter Detection",
    "SSH Protocol Versions Supported",
    "Samba Version",
    "IPMI Versions Supported",
    "Unsupported Web Server Detection",
    "TFTP Traversal Arbitrary File Access",
    "Finger .@host Unused Account Disclosure",
    "DNS Server hostname.bind Map Hostname Disclosure",
    "Microsoft .NET Version Information Disclosure",
    "Finger Service Remote Information Disclosure",
    "Web Server Directory Traversal Arbitrary File Access",
    "Web Accessible Backups",
    "iSCSI Unauthenticated Target Detection",
    "WebDAV Directory Enumeration",
    "CGI Generic SQL Injection (blind, time based)",
    "CGI Generic Header Injection",
    "CGI Generic Open Redirection",
    "CGI Generic XSS (extended patterns)",
    "Web Server Generic XSS",
    "CGI Generic Cookie Injection Scripting",
    "CGI Generic XSS (quick test)",
    "CGI Generic HTML Injections (quick test)",
    "CGI Generic XSS (comprehensive test)",
    "CGI Generic Injectable Parameter",
    "Oracle Default SID",
    "Oracle Default Accounts",
    "DNS Server Zone Transfer Information Disclosure (AXFR)",
    "SNMP Request Cisco Router Information Disclosure",
    "SNMP Query System Information Disclosure",
    "SNMP Request Network Interfaces Enumeration",
    "SNMP Query Installed Software Disclosure",
    "SNMP Query Running Process List Disclosure",
    "SNMP Query Routing Information Disclosure",
]

version_plugin_output = [
    "Symantec Encryption Server Detection",
    "Cisco IOS Version",
    "Cisco NX-OS Version",
]

nessus_xml_tree = None

def read_nessus_file(filename):
    global nessus_xml_tree
    nessus_xml_tree = ET.parse(filename)
    return nessus_xml_tree

def handle_unkwonn_banners(tree):
    root = tree.getroot()
    with open("nv-unknown-banners.txt", "w") as f:
        for host in root.findall(".//Report/ReportHost"):
            host_ip = host.attrib['name']
            for item in host.findall(".//ReportItem"):
                if item.attrib.get("pluginName") == "Unknown Service Detection: Banner Retrieval":
                    f.write(f"{host_ip}:\n")
                    plugin_output = item.findtext('plugin_output')
                    for line in plugin_output.splitlines():
                        line = line.strip()
                        if line:
                            if line.startswith("If you know") or line.startswith("identify it") or line.startswith("following output"):
                                continue
                            f.write(f"    {line}\n")
                    f.write("\n")
                    


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

            if f"{host_ip}:{port}" in services["unknown"]:
                services["unknown"].remove(f"{host_ip}:{port}")

            if f"{host_ip}:{port}" not in plugin_shortcut:
                plugin_shortcut[f"{host_ip}:{port}"] = {}

            plugin_shortcut[f"{host_ip}:{port}"][item.attrib.get("pluginName")] = item.findtext('plugin_output')


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
    return plugin_shortcut.get(ip_port, {}).get(pluginName, None)

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
        for single_output in n:
            if len(single_output.hosts) == 0: continue
            print(single_output.name, file=f)
            if single_output.should_group_total:
                for h in single_output.hosts:
                    print(f"    {h}", file=f)
            if single_output.should_group_total:
                print(file=f)

            for key,value in single_output.sub_hosts.items():
                print(f"    {key}", file=f)

    
                for z in value:
                    print(f"        {z}", file=f)
                    if single_output.name == "Service/Application Detection":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m:
                                print(f"            {m}", file=f)
                    if key in plugin_output_splitlines:
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m:
                                print(f"            {m}", file=f)
                    if key in version_plugin_output:
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m:
                                print(f"            {m}", file=f)
                    if key == "Browsable Web Directories":
                        plugin_output = get_plugin_output(key, z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[6:]:
                            print(f"            {p}", file=f)
                    elif key == "SQL Dump Files Disclosed via Web Server":
                        plugin_output = get_plugin_output(key, z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[12:]:
                            print(f"            {p}", file=f)
                    elif key == "CVS (Web-Based) Entries File Information Disclosure":
                        plugin_output = get_plugin_output(key, z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[14:]:
                            print(f"            {p}", file=f)
                    elif key == "PHP expose_php Information Disclosure":
                        plugin_output = get_plugin_output(key, z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        for p in plugin_output_s[12:]:
                            print(f"            {p}", file=f)
                    elif key == "Web Application Sitemap":
                        plugin_output = sitemap_shortcut[z]
                        urls =re.findall(r"https?://\S+", plugin_output) # type: ignore
                        for p in urls:
                            print(f"            {p}", file=f)
                    elif key == "Web Server Directory Enumeration":
                        plugin_output = get_plugin_output(key, z)
                        urls =re.findall(r"/\S+", plugin_output) # type: ignore
                        if "disc" in plugin_output: # type: ignore
                            print(f"            [NO AUTH]", file=f)
                        else:
                            print(f"            [AUTH]", file=f)
                        for p in urls:
                            print(f"            {p}", file=f)
                    elif key == "Web Server Harvested Email Addresses":
                        plugin_output = get_plugin_output(key, z)
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
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        plugin_output_s = plugin_output.split("+ CGI : ") # type: ignore
                        for p in plugin_output_s[1:]:
                                print(f"            {p.split()}", file=f)
                    elif key == "Web Server Office File Inventory":
                        plugin_output = get_plugin_output(key, z)
                        plugin_output_s = plugin_output.split() # type: ignore
                        r = plugin_output_s[12:]
                        r.reverse()
                        for p in r:
                            if p == ":":
                                break
                            print(f"            {p}", file=f)
                    elif key == "Backup Files Disclosure":
                        plugin_output = get_plugin_output(key, z)
                        urls =re.findall(r"https?://\S+", plugin_output) # type: ignore
                        for p in urls:
                            print(f"            {p}", file=f)
                    elif key == "LDAP User Enumeration":
                        plugin_output = get_plugin_output(key, z)
                        sections = plugin_output.split("|") # type: ignore
                        for s in sections:
                            print(f"            {s}", file=f)
                    elif key == "Multiple Mail Server EXPN/VRFY Information Disclosure":
                        plugin_output = get_plugin_output(key, z)
                        lines = plugin_output.splitlines() # type: ignore
                        for la in lines:
                            la = la.strip()
                            if not (la.startswith("Here") or la == ""):
                                print(f"            {la}", file=f)
                    elif key == "Apache Multiviews Arbitrary Directory Listing":
                        pattern = r"https?://.*"
                        plugin_output = get_plugin_output(key, z)
                        match = re.search(pattern, plugin_output) # type: ignore
                        if match:
                            print(f"            {match.group()}", file=f)
                    elif key == "SMB Use Host SID to Enumerate Local Users Without Credentials":
                        pattern = r"- .*"
                        plugin_output = get_plugin_output(key, z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m == "":
                                print(f"            {m}", file=f)
                    elif key == "SMB Use Host SID to Enumerate Local Users":
                        pattern = r"- .*"
                        plugin_output = get_plugin_output(key, z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m == "":
                                print(f"            {m}", file=f)
                    elif key == "SMB Use Domain SID to Enumerate Users":
                        pattern = r"- .*"
                        plugin_output = get_plugin_output(key, z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m == "":
                                print(f"            {m}", file=f)
                    elif key == "LDAP 'Domain Admins' Group Membership Enumeration":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output(key, z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "LDAP Group Enumeration":
                        pattern = r"\| .*"
                        plugin_output = get_plugin_output(key, z)
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            print(f"            {m}", file=f)
                    elif key == "Web Server Crafted Request Vendor/Version Information Disclosure":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines() # type: ignore
                        zz = False
                        for m in matches:
                            m = m.strip()
                            if zz:
                                print(f"            {m}", file=f)
                            if m.startswith("Nessus was able to gather the following information from the web server"):
                                zz = True
                    elif key == "Apple Mac OS X Find-By-Content .DS_Store Web Directory Listing":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m == "":
                                print(f"            {m}", file=f)
                    elif key == "Web Server Unconfigured - Default Install Page Present":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m == "":
                                print(f"            {m}", file=f)
                    elif key == "HTTP Methods Allowed (per directory)":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m == "":
                                print(f"            {m}", file=f)
                    elif key == "Web Server / Application favicon.ico Vendor Fingerprinting":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines() # type: ignore
                        for m in matches:
                            m = m.strip()
                            if m.startswith("Web"):
                                print(f"            {m}", file=f)
                    elif key == "External URLs":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        pattern = r".* - .*"
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            m = m.strip()
                            if not m.startswith("URL"):
                                print(f"            {m}", file=f)
                    elif key == "rsync Writeable Module Detection":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        pattern = r".* - .*"
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            m = m.strip()
                            print(f"            {m}", file=f)
                    elif key == "rsync Service Detection":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        pattern = r".* - .*"
                        matches = re.findall(pattern, plugin_output) # type: ignore
                        for m in matches:
                            m = m.strip()
                            print(f"            {m}", file=f)
                    elif key == "HTTP Server Type and Version":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        print(f"            {plugin_output.splitlines()[2]}", file=f)  # type: ignore
                    elif key == "Service Detection" or key == "Service Detection (GET request)" or key == "Service Detection (HELP request)" or key == "Service Detection: 3 ASCII Digit Code Responses" :
                        plugin_output = get_plugin_output(key, z)
                        if plugin_output is not None:
                            plugin_lines = plugin_output.splitlines() # type: ignore
                            for line in plugin_lines:
                                print(f"            {line.strip()}", file=f)  # type: ignore
                    elif key == "RPC Services Enumeration":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m:
                                print(f"            {m}", file=f)  # type: ignore
                    elif key == "IMAP Service Banner Retrieval":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines()
                        a = 0
                        for m in matches:
                            m = m.strip()
                            if m:
                                a+=1
                                if a == 2:
                                    print(f"            {m}", file=f)  # type: ignore
                    elif key == "Nonexistent Page (404) Physical Path Disclosure":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m.startswith("Path disclosed"):
                                print(f"            {m}", file=f)
                    elif key == "vsftpd Detection":
                        plugin_output = get_plugin_output(key, z)
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m.startswith("Version"):
                                print(f"            {m}", file=f)
                    elif key == "Oracle WebLogic Unsupported Version Detection":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m.startswith("Installed version"):
                                print(f"            {m}", file=f)
                    elif key == "Web Site Client Access Policy File Detection":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        print(f"            {matches[4].strip()}", file=f)  # type: ignore
                    elif key == "Web Site Cross-Domain Policy File Detection":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        print(f"            {matches[4].strip()}", file=f)  # type: ignore
                    elif key == "DCE Services Enumeration":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m.startswith("Object UUID") or m.startswith("UUID") or m.startswith("Description") or m.startswith("Windows process") or m.startswith("Type"):
                                print(f"            {m.strip()}", file=f)
                                if m.startswith("Type"):
                                    print(f"            -----", file=f)
                    elif key == "SLP Find Attributes":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m:
                                print(f"            {m.strip()}", file=f)
                    elif key == "DNP3 Detection of Device attributes":
                        plugin_output = get_plugin_output(key, z)
                        if not plugin_output:
                            continue
                        matches = plugin_output.splitlines()
                        for m in matches:
                            m = m.strip()
                            if m:
                                print(f"            {m.strip()}", file=f)





    with open(args.output_json_file, "w") as file:
        for v in l:
            json.dump(v.__dict__, file)
            file.write("\n")

def save_applications(l: list[GroupNessusScanOutput], args):
    output_dir = 'nv-applications'

    rewrite_rules = {
        "SLP Server Detection (UDP)": "SLP Server (UDP)",
        "SLP Server Detection (TCP)": "SLP Server (TCP)",
        "Microsoft Exchange Server Detection (Uncredentialed)": "Microsoft Exchange Server",
        "Microsoft SQL Server TCP": "Microsoft SQL Server",
        "NetOp Products Detection (TCP)": "NetOp Products", 
        "NetOp Products Detection (UDP)": "NetOp Products",
    }

    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for r in l:
        if r.name in ["Service/Application Detection"]:
            for key, value in r.sub_hosts.items():
                if key.endswith("Version Detection"):
                    app_name = key.replace("Version Detection", "").strip()
                elif key.endswith("Detection"):
                    app_name = key.replace("Detection", "").strip()
                elif key.endswith("Version"):
                    app_name = key.replace("Version", "").strip()
                else:
                    app_name = rewrite_rules.get(key, key)
                app_dir = os.path.join(output_dir, app_name) # type: ignore
                if not os.path.exists(app_dir):
                    os.makedirs(app_dir)
                with open(os.path.join(app_dir, "hosts.txt"), "w") as f:
                    for v in value:
                        f.write(f"{v}\n")

def post_process(l: list[GroupNessusScanOutput], args):
    output_dir = 'nv-post'

    post_http_servers = get_http_server_instances()
    for r in l:
        if r.name in ["HTTP Server Type and Version"]:
            for host in r.hosts:
                plugin_output = get_plugin_output(r.name, host)
                if not plugin_output:
                    continue
                version = plugin_output.splitlines()[2]
                for s in post_http_servers:
                    s.check(host, version)


            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            with open(os.path.join(output_dir, "http-servers.txt"), "w") as f:
                for s in post_http_servers:
                    if s.is_found:
                        s.print(f)
                        f.write("\n")



def main():
    parser = argparse.ArgumentParser(description="nessus-verifier.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Path to a Nessus file.")
    parser.add_argument('--severity0', action="store_true", help='Parse serverity 0 findings.')
    parser.add_argument('--write-unknown-banners', action="store_true", help='Writes unknown banners plugin output to a file.')
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
    save_applications(rules, args)
    post_process(rules, args)
    if args.write_unknown_banners:
        handle_unkwonn_banners(tree)
