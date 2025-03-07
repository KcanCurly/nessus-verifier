import xml.etree.ElementTree as ET
import os
import argparse
import yaml
from dataclasses import dataclass
import json

@dataclass
class GroupNessusScanOutput:
    id: int
    name: str
    plugin_ids: list[int]
    hosts: list[str]
    sub_hosts: dict[str, list[str]]
    
    def __init__(self, id, plugin_ids, name, hosts = [], sub_hosts = {}):
        self.id = id
        self.name = name
        self.plugin_ids = plugin_ids
        self.hosts = hosts
        self.sub_hosts = sub_hosts
    
    def add_host(self, name, id, host) -> bool:
        if id in self.plugin_ids:
            self.hosts.append(host)
            if name not in self.sub_hosts:
                self.sub_hosts[id] = []
            self.sub_hosts[id].append(host)
            return True
        return False
    
    @staticmethod
    def from_json(json_data):
        return GroupNessusScanOutput(**json_data)

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
    two_dirs_up = os.path.abspath(os.path.join(current_script_path, "../../"))
    rules_file_path = os.path.join(two_dirs_up, "rules.yaml")
    with open(rules_file_path, encoding='utf-8') as f:
        rule_data = yaml.safe_load(f)
        
    available_id = 0
    for rule in rule_data:
        new_rule = GroupNessusScanOutput(rule['id'], rule['plugin-ids'], rule['name'])
        rules.append(new_rule)
        available_id = available_id + 1

    available_id = available_id +1
    for n in l:
        found = False
        for rule in rules:
            if rule.add_host(n.name, n.plugin_id, n.host_port):
                found = True
                break
        
        # No rule in rules.yaml so we make its own rule if its not on info severity
        if not found and n.severity != "0":
            new_rule = GroupNessusScanOutput(available_id, [n.plugin_id], n.name)
            new_rule.add_host(n.name, n.plugin_id, n.host_port)
            rules.append(new_rule)
            available_id = available_id + 1
        
    return rules

def validate(l: list[GroupNessusScanOutput], args):
    with open(args.output_file, "w") as f:
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
                    
    with open(args.output_json_file, "w") as file:
        for v in l:
            json.dump(v.__dict__, file)
            file.write("\n")


def main2(args):
    nessus_file_content = read_nessus_file(args.file)
    output = parse_nessus_output(nessus_file_content)
    rules = group_up(output)
    validate(rules, args)

def main():
    parser = argparse.ArgumentParser(description='Process Nessus file and output results to file.')
    parser.add_argument('-f', '--file', type=str, required=True, help='Path to a Nessus file')
    parser.add_argument('-o', '--output-file', type=str, required=False, default="output.txt", help='Path to a Nessus file')
    parser.add_argument('-oj', '--output-json-file', type=str, required=False, default="output.json", help='Path to a Nessus file')
    args = parser.parse_args()
    main2(args)
        
if __name__ == '__main__':
    main()