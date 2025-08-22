#!/usr/bin/env python3
import argparse
import ipaddress
import xml.etree.ElementTree as ET

def filter_nessus(input_file, output_file, subnets):
    # Parse subnets into ip_network objects
    networks = [ipaddress.ip_network(s) for s in subnets]

    # Parse Nessus XML
    tree = ET.parse(input_file)
    root = tree.getroot()

    # Find <Report> block
    report = root.find("Report")

    # Collect hosts to remove
    to_remove = []
    for host in report.findall("ReportHost"):
        ip = host.get("name")
        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            continue  # skip if not a valid IP

        # Keep only if matches ANY subnet
        if not any(ip_addr in net for net in networks):
            to_remove.append(host)

    # Remove non-matching hosts
    for host in to_remove:
        report.remove(host)

    # Save filtered Nessus file
    tree.write(output_file, encoding="utf-8", xml_declaration=True)

def main():
    parser = argparse.ArgumentParser(description="Filter Nessus file by subnets")
    parser.add_argument("-f", "--file", required=True, help="Input .nessus file")
    parser.add_argument("-o", "--output", required=True, help="Output .nessus file")
    parser.add_argument(
        "-s", "--subnets", required=True, nargs="+",
        help="Space-delimited list of subnets (e.g. -s 10.10.10.0/24 192.168.1.0/24)"
    )
    args = parser.parse_args()

    filter_nessus(args.file, args.output, args.subnets)

if __name__ == "__main__":
    main()