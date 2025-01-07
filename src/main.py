import xml.etree.ElementTree as ET
import os
from modules import ssh
import argparse

# Function to parse the Nessus file (.nessus format) and extract services and associated hosts
def parse_nessus_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Dictionary to store services and their associated hosts
    services = {}

    # Iterate through all host elements in the XML
    for host in root.findall(".//Report/ReportHost"):
        host_ip = host.attrib['name']  # Extract the host IP

        # Iterate through all the services (plugins) for this host
        for item in host.findall(".//ReportItem"):
            service_name = item.attrib.get('svc_name', '').lower()
            port = item.attrib.get('port', '')

            # Skip services ending with "?" (uncertain services)
            if service_name.endswith('?') or service_name == "general" or service_name == "unknown":
                continue

            # Create a directory for the service if it doesn't exist
            if service_name not in services:
                services[service_name] = set()

            # Add host IP to the service's list
            services[service_name].add(f"{host_ip}:{port}")

    return services

# Function to create directories and save hosts in 'hosts.txt'
def save_services_and_hosts(services):
    output_dir = 'ports'

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
                
def handle_services():
    cdir = os.curdir
    
    if os.path.isdir(cdir+ "/ports/ssh"):
        ssh.check(cdir + "/ports/ssh")

# Main function to execute the script
def main():
    parser = argparse.ArgumentParser(description="nessus-verifier.")
    parser.add_argument("-f", "--file", type=str, required=False, help="Nessus file.")
    args = parser.parse_args()
    nessus_file = args.file
    services = parse_nessus_file(nessus_file)
    save_services_and_hosts(services)
    # handle_services()

if __name__ == '__main__':
    main()
