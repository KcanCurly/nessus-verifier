import subprocess
import argparse
import os
import re

protocol1 = []
versions = {}

cve_dict = {
    
}

vuln_kex = set()
vuln_mac = set()
vuln_key = set()
vuln_cipher = set()

vuln_hosts = set()

creds = [
"root:calvin",
"root:root",
"root:toor",
"administrator:password",
"NetLinx:password",
"administrator:Amx1234!",
"amx:password",
"amx:Amx1234!",
"admin:1988",
"admin:admin",
"Administrator:Vision2",
"cisco:cisco",
"c-comatic:xrtwk318",
"root:qwasyx21",
"admin:insecure",
"pi:raspberry",
"user:user",
"root:default",
"root:leostream",
"leo:leo",
"localadmin:localadmin",
"fwupgrade:fwupgrade",
"root:rootpasswd",
"admin:password",
"root:timeserver",
"admin:motorola",
"cloudera:cloudera",
"root:p@ck3tf3nc3",
"apc:apc",
"device:apc",
"eurek:eurek",
"netscreen:netscreen",
"admin:avocent",
"root:linux",
"sconsole:12345",
"root:5up",
"cirros:cubswin:)",
"root:uClinux",
"root:alpine",
"root:dottie",
"root:arcsight",
"root:unitrends1",
"vagrant:vagrant",
"root:vagrant",
"m202:m202",
"demo:fai",
"root:fai",
"root:ceadmin",
"maint:password",
"root:palosanto",
"root:ubuntu1404",
"root:cubox-i",
"debian:debian",
"root:debian",
"root:xoa",
"root:sipwise",
"debian:temppwd",
"root:sixaola",
"debian:sixaola",
"myshake:shakeme",
"stackato:stackato",
"root:screencast",
"root:stxadmin",
"root:nosoup4u",
"root:indigo",
"root:video",
"default:video",
"default:",
"ftp:video",
"nexthink:123456",
"ubnt:ubnt",
"root:ubnt",
"sansforensics:forensics",
"elk_user:forensics",
"osboxes:osboxes.org",
"root:osboxes.org",
"sans:training",
"user:password",
"misp:Password1234",
"hxeadm:HXEHana1",
"acitoolkit:acitoolkit",
"osbash:osbash",
"enisa:enisa",
"geosolutions:Geos",
"pyimagesearch:deeplearning",
"root:NM1$88",
"remnux:malware",
"hunter:hunter",
"plexuser:rasplex",
"root:openelec",
"root:rasplex",
"root:plex",
"root:openmediavault",
"root:ys123456",
"root:libreelec",
"openhabian:openhabian",
"admin:ManagementConsole2015",
"public:publicpass",
"admin:hipchat",
"nao:nao",
"support:symantec",
"root:max2play",
"admin:pfsense",
"root:root01",
"root:nas4free",
"USERID:PASSW0RD",
"Administrator:p@ssw0rd",
"root:freenas",
"root:cxlinux",
"admin:symbol",
"admin:Symbol",
"admin:superuser",
"admin:admin123",
"root:D13HH[",
"root:blackarch",
"root:dasdec1",
"root:7ujMko0admin",
"root:7ujMko0vizxv",
"root:Zte521",
"root:zlxx.",
"root:compass",
"hacker:compass",
"samurai:samurai",
"ubuntu:ubuntu",
"root:openvpnas",
"misp:Password1234",
"root:wazuh",
"student:password123",
"root:roottoor",
"centos:reverse",
"root:reverse",
"zyfwp:PrOw!aN_fXp",
"manage:!manage",
"monitor:!monitor",
"oracle:oracle",
"admin:changeme",
"root:changeme",
"admin:welcome1",
"lpar2rrd:xorux4you",
"admin:YourPaSsWoRd",
"apcsetup:apcsetup",
"admin:service.",
"admin:admin01",
"linuxadmin:linuxadmin"
]


def check(directory_path, hosts = "hosts.txt"):
    hosts_path = os.path.join(directory_path, hosts)
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()]  # Remove empty lines and whitespace
        
    # Define regular expression patterns
    protocol_pattern = r"Remote protocol version (\d+\.\d+)"
    software_pattern = r"remote software version ([\w_]+\.*.*)"
    
    print("Running ssh version capturer")
    # Iterate over each host and run the command
    for host in hosts:
        print(host)
        ip = host
        port = 22
        if ":" in host:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
        command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", ip]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            print(result.stderr)
            
            # Find matches using the patterns
            protocol_match = re.search(protocol_pattern, result.stderr)
            software_match = re.search(software_pattern, result.stderr)
            
            if protocol_match:
                protocol_version = protocol_match.group(1)
                if protocol_version != "2.0":
                    protocol1.append(ip + ":" + port)
            else: print(f"Could not found protocol version for {ip + ":" + port}")
            
            if software_match:
                software_version = software_match.group(1)
                if software_version not in versions:
                    versions[software_version] = []
                versions[software_version].append(ip + ":" + port)
            else: print(f"Could not found software version for {ip + ":" + port}")
                

        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            print(e)
            continue
    
    if len(protocol1) > 0:
        print("Protocol Version 1:")
        for p in protocol1:
            print(f"\t{p}")
    
    for index, (key, value) in enumerate(versions.items()):
        print(key + ":")
        for v in value:
            print(f"\t{v}")
        
    ######################################
    print("Running ssh audit")
    for host in hosts:
        command = ["ssh-audit", host]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            lines = result.stdout.splitlines()
            is_vul = False
            for line in lines:
                if "0;31m(rec)" in line:
                    is_vul = True
                    
                    if "kex" in line:
                        vuln_kex.add(line.split()[1][1:])
                    elif "mac" in line:
                        vuln_mac.add(line.split()[1][1:])
                    elif "key" in line:
                        vuln_key.add(line.split()[1][1:])
                elif "vulnerable to the Terrapin attack" in line:
                    is_vul = True
                    vuln_cipher.add(line.split()[1][1:])
        
            if is_vul:
                vuln_hosts.add(host)
        
        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            continue
    
    if len(vuln_kex) > 0:
        print("Vulnerable KEX algorithms found:")
        for k in vuln_kex:
            print(f"\t{k}")
        print()
        
    if len(vuln_mac) > 0:
        print("Vulnerable MAC algorithms found:")
        for k in vuln_mac:
            print(f"\t{k}")
        print()
            
    if len(vuln_key) > 0:
        print("Vulnerable Host-Key algorithms found:")
        for k in vuln_key:
            print(f"\t{k}")
        print()
    
    if len(vuln_cipher) > 0:
        print("Vulnerable Cipher algorithms found:")
        for k in vuln_cipher:
            print(f"\t{k}")
        print()
            
    if len(vuln_hosts) > 0:
        print("Vulnerable hosts found:")
        for k in vuln_hosts:
            print(f"\t{k}")
            
            
            
    ######################################

    with open(os.path.join(directory_path, "creds.txt"), "w") as file:
        for item in creds:
            file.write(f"{item}\n")
    try:
        print("Running sshwhirl, this might take a while")
        command = ["sshwhirl.py", hosts_path, os.path.join(directory_path, "creds.txt"), os.path.join(directory_path, "result.txt")]
        print(command)
        result = subprocess.run(command, text=True, capture_output=True)
        print(result.stdout)
        print(result.stderr)
    except e:
        print(e)
    

def main():
    parser = argparse.ArgumentParser(description="SSH module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")