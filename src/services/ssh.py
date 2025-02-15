import subprocess
import argparse
import re
from src.utilities.utilities import get_hosts_from_file
from rich.live import Live
from rich.progress import TextColumn, Progress, BarColumn, TimeElapsedColumn, TaskID
from rich.table import Column
from rich.console import Group
from rich.panel import Panel
from collections import deque
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor
import threading

cve_dict = {
    
}

main_creds = [
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
"linuxadmin:linuxadmin",
"rwa:rwa",
]

def version_check(hosts: list[str]):
    protocol_pattern = r"Remote protocol version (.*),"
    software_pattern = r"remote software version (.*)"
    protocol1 = []
    versions = {}
    for host in hosts:
        ip = host.split(":")[0]
        port  = host.split(":")[1]

        command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", ip]
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            
            # Find matches using the patterns
            protocol_match = re.search(protocol_pattern, result.stderr)
            software_match = re.search(software_pattern, result.stderr)
            
            if protocol_match:
                protocol_version = protocol_match.group(1)
                if protocol_version != "2.0":
                    protocol1.append(host)
            # else: print(f"Could not found protocol version for {host}")
            
            if software_match:
                software_version = software_match.group(1)
                if " " in software_version:
                    software_version = software_version.split("")[0]
                if software_version not in versions:
                    versions[software_version] = []
                versions[software_version].append(host)
            # else: print(f"Could not found software version for {host")
                

        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            continue
    
    if len(protocol1) > 0:
        print("Protocol Version 1:")
        for p in protocol1:
            print(f"\t{p}")
    
    for index, (key, value) in enumerate(versions.items()):
        print(key + ":")
        for v in value:
            print(f"\t{v}")
    
def ssh_audit_check(hosts: list[str]):
    for host in hosts:
        command = ["ssh-audit", "--skip-rate-test", host]
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



def check(directory_path, args, hosts):
    hosts = get_hosts_from_file(hosts)
    
    version_check(hosts)
    ssh_audit_check(hosts)
        

def audit_single(progress: Progress, task_id: TaskID, console: Console, host, output, timeout, verbose):
    vuln_kex = set()
    vuln_mac = set()
    vuln_key = set()
    vuln_cipher = set()
    vuln_hosts = set()
    vuln_terrapin = set()
    command = ["ssh-audit", "--skip-rate-test", host]
    try:
        # Execute the command and capture the output
        result = subprocess.run(command, text=True, capture_output=True)
        lines = result.stdout.splitlines()
        is_vul = False
        for line in lines:
            if "(rec)" in line:
                is_vul = True
                
                if "kex algorithm to remove" in line:
                    vuln_kex.add(line.split()[1][1:])
                elif "mac algorithm to remove" in line:
                    vuln_mac.add(line.split()[1][1:])
                elif "key algorithm to remove" in line:
                    vuln_key.add(line.split()[1][1:])
                elif "enc algorithm to remove" in line:
                    vuln_cipher.add(line.split()[1][1:])
            elif "vulnerable to the Terrapin attack" in line:
                is_vul = True
                vuln_terrapin.add(line.split()[1][1:])
    
        if is_vul:
            vuln_hosts.add(host)
        console.print(f"Successfully processed {host}")
    except Exception as e:
        console.log(f"Error on {host}: {e}")
    progress.update(task_id, advance=1)
    return (vuln_kex, vuln_mac, vuln_key, vuln_cipher, vuln_hosts, vuln_terrapin)

def audit(args):
    overall_progress = Progress(
    TimeElapsedColumn(), BarColumn(), TextColumn("{task.completed}/{task.total}")
)
    overall_task_id = overall_progress.add_task("", start=False)
    console = Console(height=10)
    
    vuln_kex = set()
    vuln_mac = set()
    vuln_key = set()
    vuln_cipher = set()
    vuln_hosts = set()
    vuln_terrapin = set()
    
    hosts = get_hosts_from_file(args.file)
    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(hosts))
        overall_progress.start_task(overall_task_id)
        with ThreadPoolExecutor(args.threads) as executor:
            for host in hosts:
                futures = [executor.submit(audit_single, overall_progress, overall_task_id, console, host, args.output, args.timeout, args.verbose)]
            results = [f.result() for f in futures]
    for r in results:
        vuln_kex = vuln_kex | r[0]
        vuln_mac = vuln_mac | r[1]
        vuln_key = vuln_key | r[2]
        vuln_cipher = vuln_cipher | r[3]
        vuln_hosts = vuln_hosts | r[4]
        vuln_terrapin = vuln_terrapin | r[5]
    
    
    if len(vuln_kex) > 0:
        print("Vulnerable KEX algorithms:")
        for k in vuln_kex:
            print(f"\t{k}")
        print()
        
    if len(vuln_mac) > 0:
        print("Vulnerable MAC algorithms:")
        for k in vuln_mac:
            print(f"\t{k}")
        print()
            
    if len(vuln_key) > 0:
        print("Vulnerable Host-Key algorithms:")
        for k in vuln_key:
            print(f"\t{k}")
        print()
    
    if len(vuln_cipher) > 0:
        print("Vulnerable Cipher algorithms:")
        for k in vuln_cipher:
            print(f"\t{k}")
        print()
            
    if len(vuln_hosts) > 0:
        print("Vulnerable hosts:")
        for k in vuln_hosts:
            print(f"\t{k}")
            
    if len(vuln_terrapin) > 0:
        print("Vulnerable Terraping hosts:")
        for k in vuln_terrapin:
            print(f"\t{k}")

def main():
    parser = argparse.ArgumentParser(description="SSH module of nessus-verifier.")
    parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    subparsers = parser.add_subparsers(dest="command")
    
    audit_parser = subparsers.add_parser("audit", help="Run ssh-audit on targets")
    audit_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    audit_parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    audit_parser.add_argument("--timeout", type=int, default=3, help="Timeout (Default = 3).")
    audit_parser.set_defaults(func=audit)


    
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
    
