#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET

import cidr_man

def filter_nessus(input_file, output_file, include, exclude):
    # Parse Nessus XML
    tree = ET.parse(input_file)
    root = tree.getroot()

    # Find <Report> block
    report = root.find("Report")

    # Collect hosts to remove
    to_remove = []
    for host in report.findall("ReportHost"):
        ip = host.get("name")

        if include:
            if not any(cidr_man.CIDR(ip) in net for net in include):
                to_remove.append(host)

        if exclude:
            if any(cidr_man.CIDR(ip) in net for net in exclude):
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
    parser.add_argument('--include-list', type=str, required=False, help='Only process IPs that is in the given file.')
    parser.add_argument('--exclude-list', type=str, required=False, help='Only process IPs that is NOT in the given file.')
    args = parser.parse_args()

    include = None
    exclude = None

    if args.include_list:
        with open(args.include_list, "r") as f:
            include = [cidr_man.CIDR(i) for i in f]

    if args.exclude_list:
        with open(args.exclude_list, "r") as f:
            exclude = [cidr_man.CIDR(i) for i in f]

    filter_nessus(args.file, args.output, include, exclude)

if __name__ == "__main__":
    main()