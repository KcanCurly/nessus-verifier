import xml.etree.ElementTree as ET
import os
import argparse
import re

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

                ssl_match = re.search(r"SSL\s+:\s+(yes|no)", item.findtext('plugin_output'))
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

def save_urls(urls):
    output_file = "urls.txt"
    
    with open(output_file, 'w') as f:
        for url in urls:
            f.write(f"{url}\n")
    
    

def main():
    parser = argparse.ArgumentParser(description="nessus-verifier.")
    parser.add_argument("-f", "--file", type=str, required=False, help="Nessus file.")
    args = parser.parse_args()
    nessus_file = args.file
    (services, urls) = parse_nessus_file(nessus_file)
    save_services(services)
    save_urls(urls)
    
if __name__ == "__main__":
    main()