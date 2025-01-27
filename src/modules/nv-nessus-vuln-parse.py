import xml.etree.ElementTree as ET
import os
import argparse
import yaml

class GroupNessusScanOutput:
    hosts = []
    sub_hosts = {}
    
    def __init__(self, plugin_ids, name):
        self.name = name
        self.plugin_ids = plugin_ids
        self.hosts = []
        self.sub_hosts = {}
        pass
    
    def add_host(self, name, id, host) -> bool:
        if id in self.plugin_ids:
            self.hosts.append(host)
            if name not in self.sub_hosts:
                self.sub_hosts[name] = []
            self.sub_hosts[name].append(host)
            return True
        return False

class NessusScanOutput:
    def __init__(self, plugin_id, name, description, severity, host_port, output, cve):
        self.plugin_id = plugin_id
        self.name = name
        self.description = description
        self.severity = severity
        self.host_port = host_port
        self.output = output
        self.cve = cve

def parse_nessus_output(nessus_xml) -> list[NessusScanOutput]:
    print("[+] Parsing Nessus XML...")
    """
    Parses Nessus XML output and returns a list of NessusScanOutput objects.
    """
    nessus_scan_output = []

    root = ET.fromstring(nessus_xml)

    for host in root.iter('ReportHost'):
        host_properties = host.find('HostProperties')
        ip_address = host_properties.findtext("./tag[@name='host-ip']")

        for item in host.iter('ReportItem'):
            plugin_id = int(item.get('pluginID'))
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
    two_dirs_up = os.path.abspath(os.path.join(current_script_path, "../../../"))
    rules_file_path = os.path.join(two_dirs_up, "rules.yaml")
    with open(rules_file_path, encoding='utf-8') as f:
        rule_data = yaml.safe_load(f)
        
    for rule in rule_data:
        new_rule = GroupNessusScanOutput(rule['plugin-ids'], rule['name'])
        rules.append(new_rule)

    for n in l:
        found = False
        for rule in rules:
            if rule.add_host(n.name, n.plugin_id, n.host_port):
                found = True
                break
        
        # No rule in rules.yaml so we make its own rule if its not on info severity
        if not found and n.severity != "0":
            new_rule = GroupNessusScanOutput([n.plugin_id], n.name)
            new_rule.add_host(n.name, n.plugin_id, n.host_port)
            rules.append(new_rule)
        
    return rules

def validate(l: list[GroupNessusScanOutput]):
    with open("output.txt", "w") as f:
        for a in l[1:]: # We skip first one since its on ignore list
            print(a.name, file=f)
            for z in a.hosts:
                print(f"\t{z}", file=f)
            print(file=f)
            print(file=f)
            if len(a.sub_hosts.items()) == 1: continue
            for k,v in a.sub_hosts.items():
                print(f"\t{k}", file=f)
                for z in v:
                    print(f"\t\t{z}", file=f)


def main():
    parser = argparse.ArgumentParser(description='Process Nessus file and output results to file.')
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to a Nessus file')
    args = parser.parse_args()
    nessus_file_content = read_nessus_file(args.file)
    output = parse_nessus_output(nessus_file_content)
    rules = group_up(output)
    validate(rules)
        
if __name__ == '__main__':
    main()