#!/usr/bin/env python3
import argparse, argcomplete
import copy
import xml.etree.ElementTree as ET
import cidr_man
from openpyxl import Workbook
import csv
import ipaddress
import i18n

def filter_nessus(args):
    input_file = args.file
    output_file = args.output
    include = args.include
    exclude = args.exclude
    # Parse Nessus XML
    tree = ET.parse(input_file)
    root = tree.getroot()

    if exclude:
        with open(exclude, 'r') as f:
            exclude = [line.strip() for line in f if line.strip()]
    if include:
        with open(include, 'r') as f:
            include = [line.strip() for line in f if line.strip()]

    # Find <Report> block
    report = root.find("Report")

    # Collect hosts to remove
    to_remove = []
    for host in report.findall("ReportHost"): # type: ignore
        ip = host.get("name")

        if include:
            if not any(cidr_man.CIDR(ip) in cidr_man.CIDR(net) for net in include):
                to_remove.append(host)

        if exclude:
            for net in exclude:
                try:
                    if cidr_man.CIDR(ip) in cidr_man.CIDR(net):
                            to_remove.append(host)
                            break
                except Exception as e:
                    print(f"Error processing CIDR {ip} - {net}: {e}")
            #if any(cidr_man.CIDR(ip) in cidr_man.CIDR(net) for net in exclude):
            #    to_remove.append(host)


    # Remove non-matching hosts
    for host in to_remove:
        report.remove(host) # type: ignore

    # Save filtered Nessus file
    tree.write(output_file, encoding="utf-8", xml_declaration=True)

def split(args):
    input_file = args.file
    n = args.number


    # Parse Nessus XML
    tree = ET.parse(input_file)
    root = tree.getroot()

    # Find <Report> block
    report = root.find("Report")
    count  = len(report.findall("ReportHost")) # type: ignore
    magic_number = count // n

    new_root = copy.deepcopy(root)

    new_report = new_root.find(".//Report")

    # Remove all hosts
    for rh in new_report.findall("ReportHost"): # type: ignore
        new_report.remove(rh) # type: ignore

    new_roots = [copy.deepcopy(new_root) for _ in range(0, n)]


    for i, host in enumerate(report.findall("ReportHost")): # type: ignore
        i += 1
        index = i // magic_number
        if index > len(new_roots) - 1:
            index = len(new_roots) - 1
        new_roots[index].find(".//Report").append(host) # type: ignore

    new_name = input_file.replace(".nessus", "")

    for i, root in enumerate(new_roots):
        ET.ElementTree(root).write(
            new_name + "_s" + str(i) + ".nessus",
            encoding="utf-8",
        )

def portreport(args):
    input_file = args.file

    tree = ET.parse(input_file)
    root = tree.getroot()

    #h = {}
#
    #wb = Workbook()
    #wb.remove(wb.active) # type: ignore
    #wb.create_sheet("portScanData")
    #ws = wb["portScanData"]
    #ws.append(["IP Address", "Protocol", "Port", "Sevice Name"])
#
    #for host in root.findall(".//Report/ReportHost"):
    #    host_ip = host.attrib['name']  # Extract the host IP
    #    for item in host.findall(".//ReportItem"):
    #        service_name = item.attrib.get('svc_name', '').lower()
    #        port = item.attrib.get('port', 0)
    #        protocol = item.attrib.get('protocol')
#
    #        if not port: # Skip port 0
    #            continue
    #        if service_name == "general":
    #            continue
    #        if host_ip not in h:
    #            h[host_ip] = set()
    #        if not port in h[host_ip]:
    #            ws.append([host_ip, protocol, port, service_name])
    #            h[host_ip].add(port)
#
    #wb.save("portreport.xlsx")
#
    h = {}

    with open("portreport.csv", mode="w", newline='') as file:
        writer = csv.writer(file, delimiter=";")
        writer.writerow(["IP Address", "Protocol", "Port", "Service Name"])
        for host in root.findall(".//Report/ReportHost"):
            host_ip = host.attrib['name']  # Extract the host IP
            for item in host.findall(".//ReportItem"):
                service_name = item.attrib.get('svc_name', '').lower()
                port = item.attrib.get('port', 0)
                protocol = item.attrib.get('protocol')

                if not port: # Skip port 0
                    continue
                if service_name == "general":
                    continue
                if host_ip not in h:
                    h[host_ip] = set()
                if not port in h[host_ip]:
                    writer.writerow([host_ip, protocol, port, service_name])
                    h[host_ip].add(port)



def checkaccess(args):
    input_file = args.file
    scope_file = args.scope
    ignore_ports = parse_ports(args.ignore_ports) if args.ignore_ports else []

    # Load scope CIDRs
    scope_nets = []
    found_ips = set()
    with open(scope_file, 'r') as sf:
        for line in sf:
            scope_nets.append(line.strip())

    tree = ET.parse(input_file)
    root = tree.getroot()

    report = root.find("Report")

    for host in report.findall("ReportHost"): # type: ignore
        ip = host.get("name")
        port = host.get('port', 0)
        if ip and port and int(port) not in ignore_ports:
            found_ips.add(ip)

    for scope in scope_nets:
        if "/" in scope:
            not_found = expand_cidr_range(scope)
            for ip in found_ips:
                if ip in cidr_man.CIDR(scope):
                    not_found.remove(ip)
            if len(not_found) > 0:
                print(i18n.t('main.check_access', name=scope))
                for ip in not_found:
                    print(f"  {ip}")
        else:
            if scope not in found_ips:
                print(f"{scope}")

def expand_cidr_range(cidr):
    """
    Expand CIDR ranges
    """
    return [str(host) for host in ipaddress.ip_network(cidr, strict=False).hosts()]  # Expand the CIDR range

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
    parser = argparse.ArgumentParser(description="Nessus Module")
    subparsers = parser.add_subparsers(dest="command", required=True)
    # Command 1
    p1 = subparsers.add_parser("filter", help="Filters nessus file according to include")
    p1.add_argument("-f", "--file", required=True, help="Input .nessus file")
    p1.add_argument("-o", "--output", required=True, help="Output .nessus file")
    p1.add_argument("-i", '--include', type=str, required=False, help='Only process IPs that is in the given file.')
    p1.add_argument("-e", '--exclude', type=str, required=False, help='Only process IPs that is NOT in the given file.')
    p1.set_defaults(func=filter_nessus)

    # Command 2
    p2 = subparsers.add_parser("split", help="Splits the nessus file evenly across multiple files")
    p2.add_argument("-f", "--file", required=True, help="Input .nessus file")
    p2.add_argument("-n", "--number", type=int, required=True, help="Number of files")
    p2.set_defaults(func=split)

    # Command 3
    p3 = subparsers.add_parser("portreport", help="Port Report")
    p3.add_argument("-f", "--file", required=True, help="Input .nessus file")
    p3.set_defaults(func=portreport)

    # Command 4
    p4 = subparsers.add_parser("accesscheck", help="Checks if any ports are accessible on given scope")
    p4.add_argument("-f", "--file", required=True, help="Input .nessus file")
    p4.add_argument("-s", "--scope", required=True, help="Input scope file")
    p4.add_argument("--ignore-ports", type=parse_ports, help="Comma separated list of ports to ignore",  nargs="+", required=False)
    p4.set_defaults(func=checkaccess)

    args = parser.parse_args()
    argcomplete.autocomplete(parser)
    args.func(args)

if __name__ == "__main__":
    main()