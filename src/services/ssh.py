import subprocess
import argparse
import re
from src.utilities.utilities import get_hosts_from_file, get_classic_progress, get_classic_console
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed

cve_dict = {
    
}

class Audit_Vuln_Data:
    def __init__(self, host: str, is_vuln: bool, is_terrapin: bool, vuln_kex: list[str], vuln_mac: list[str], vuln_key: list[str], vuln_cipher):
        self.host = host
        self.is_vuln = is_vuln
        self.is_terrapin = is_terrapin
        self.vuln_kex = vuln_kex
        self.vuln_mac = vuln_mac
        self.vuln_key = vuln_key
        self.vuln_cipher = vuln_cipher

class Version_Vuln_Data:
    def __init__(self, host: str, version: str, protocol: str):
        self.host = host
        self.version = version
        self.protocol = protocol

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

        
def audit_single(progress: Progress, task_id: TaskID, console: Console, host: str, output: str, timeout: int, verbose: bool) -> Audit_Vuln_Data:
    vuln_kex = []
    vuln_mac = []
    vuln_key = []
    vuln_cipher = []
    if verbose: console.print(f"Starting processing {host}")
    command = ["ssh-audit", "--skip-rate-test", "-t", str(timeout), host]
    try:
        # Execute the command and capture the output
        result = subprocess.run(command, text=True, capture_output=True)
        lines = result.stdout.splitlines()
        is_vul = False
        is_terrapin = False
        for line in lines:
            if "(rec)" in line:
                is_vul = True
                
                if "kex algorithm to remove" in line:
                    vuln_kex.append(line.split()[1][1:])
                elif "mac algorithm to remove" in line:
                    vuln_mac.append(line.split()[1][1:])
                elif "key algorithm to remove" in line:
                    vuln_key.append(line.split()[1][1:])
                elif "enc algorithm to remove" in line:
                    vuln_cipher.append(line.split()[1][1:])
            elif "vulnerable to the Terrapin attack" in line:
                is_vul = True
                is_terrapin = True

        if verbose: console.print(f"Successfully processed {host}: {"Terrapin," if is_terrapin else ""} {str(len(vuln_kex))} KEX, {str(len(vuln_mac))} MAC, {str(len(vuln_key))} HOST-KEY, {str(len(vuln_cipher))} CIPHER")
        
        progress.update(task_id, advance=1)
        return Audit_Vuln_Data(host, is_vul, is_terrapin, vuln_kex, vuln_mac, vuln_key, vuln_cipher)
    except Exception as e:
        if verbose: console.log(f"Error on {host}: {e}")
        progress.update(task_id, advance=1)
        return Audit_Vuln_Data(host, False, None, None, None, None, None)

def audit_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    overall_progress = get_classic_progress()
    overall_task_id = overall_progress.add_task("", start=False)
    console = get_classic_console(force_terminal=True)
    
    vuln_kex = set()
    vuln_mac = set()
    vuln_key = set()
    vuln_cipher = set()
    vuln_hosts = set()
    vuln_terrapin = set()
    

    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(l))
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[Audit_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                future = executor.submit(audit_single, overall_progress, overall_task_id, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                results.append(a.result())
                
    for r in results:
        if r.is_vuln:
            vuln_hosts.add(r.host)
            vuln_kex.update(r.vuln_kex)
            vuln_mac.update(r.vuln_mac)
            vuln_key.update(r.vuln_kex)
            vuln_cipher.update(r.vuln_cipher)
        if r.is_terrapin:
            vuln_terrapin.add(r.host)
    
    if len(vuln_kex) > 0:
        print("Vulnerable KEX algorithms:")
        for k in vuln_kex:
            print(f"    {k}")
        print()
        
    if len(vuln_mac) > 0:
        print("Vulnerable MAC algorithms:")
        for k in vuln_mac:
            print(f"    {k}")
        print()
            
    if len(vuln_key) > 0:
        print("Vulnerable Host-Key algorithms:")
        for k in vuln_key:
            print(f"    {k}")
        print()
    
    if len(vuln_cipher) > 0:
        print("Vulnerable Cipher algorithms:")
        for k in vuln_cipher:
            print(f"    {k}")
        print()
            
    if len(vuln_hosts) > 0:
        print("Vulnerable hosts:")
        for k in vuln_hosts:
            print(f"    {k}")
            
    if len(vuln_terrapin) > 0:
        print("Vulnerable Terraping hosts:")
        for k in vuln_terrapin:
            print(f"    {k}")

def audit_console(args):
    audit_nv(get_hosts_from_file(args.file), args.output, args.threads, args.timeout, args.verbose)


def version_single(progress: Progress, task_id: TaskID, console: Console, host: str, output: str, timeout: int, verbose: bool) -> Version_Vuln_Data:
    ip, port = host.split(":", 1)
    
    protocol_pattern = r"Remote protocol version (.*),"
    software_pattern = r"remote software version (.*)"
    
    protocol = ""
    version = ""
    
    if verbose: console.print(f"Starting processing {host}")
    command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", ip]
    try:
        # Execute the command and capture the output
        result = subprocess.run(command, text=True, capture_output=True)
        
        # Find matches using the patterns
        protocol_match = re.search(protocol_pattern, result.stderr)
        software_match = re.search(software_pattern, result.stderr)
        
        if protocol_match:
            protocol = protocol_match.group(1)
        
        if software_match:
            version = software_match.group(1)
            if " " in version:
                version = version.split(" ")[0]

        if verbose: console.print(f"Successfully processed {host}: {f"Version: {version}," if version else "No version found,"} {f"Protocol: {protocol}" if protocol else "No protocol found"}")
        progress.update(task_id, advance=1)
        return Version_Vuln_Data(host, version, protocol)
    except Exception as e:
        progress.update(task_id, advance=1)
        if verbose: console.log(f"Error on {host}: {e}")
        return Version_Vuln_Data(host, version, protocol)

def version_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    overall_progress = get_classic_progress()
    overall_task_id = overall_progress.add_task("", start=False)
    console = get_classic_console(force_terminal=True)

    
    protocol1 = []
    versions = {}
    
    with Live(overall_progress, console=console):
        overall_progress.update(overall_task_id, total=len(l))
        overall_progress.start_task(overall_task_id)
        futures = []
        results: list[Version_Vuln_Data] = []
        with ThreadPoolExecutor(threads) as executor:
            for host in l:
                future = executor.submit(version_single, overall_progress, overall_task_id, console, host, output, timeout, verbose)
                futures.append(future)
            for a in as_completed(futures):
                results.append(a.result())
             
    for r in results:
        if r.protocol and r.protocol != "2.0":
            protocol1.append(r.host)
        if r.version:
            if r.version not in versions:
                versions[r.version] = []
            versions[r.version].append(r.host)
            
    if len(protocol1) > 0:
        print("Protocol Version 1:")
        for p in protocol1:
            print(f"    {p}")
    
    versions = dict(sorted(versions.items(), reverse=True))
    if len(versions) > 0:
        print("SSH Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")


def version_console(args):
    version_nv(get_hosts_from_file(args.file), args.output, args.threads, args.timeout, args.verbose)
    
def all_console(args):
    audit_console(args)
    version_console(args)

def main():
    parser = argparse.ArgumentParser(description="SSH module of nessus-verifier.")
    subparsers = parser.add_subparsers(dest="command")
    
    all_parser = subparsers.add_parser("all", help="Run all related subcommands")
    all_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    all_parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    all_parser.add_argument("--timeout", type=int, default=3, help="Timeout (Default = 3).")
    all_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    all_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    all_parser.set_defaults(func=all_console)
    
    audit_parser = subparsers.add_parser("audit", help="Run ssh-audit on targets")
    audit_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    audit_parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    audit_parser.add_argument("--timeout", type=int, default=3, help="Timeout (Default = 3).")
    audit_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    audit_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    audit_parser.set_defaults(func=audit_console)
    
    version_parser = subparsers.add_parser("version", help="Run SSH version check on targets")
    version_parser.add_argument("-f", "--file", type=str, required=False, help="Path to a file containing a list of hosts, each in 'ip:port' format, one per line.")
    version_parser.add_argument("-o", "--output", type=str, required=False, help="Output file.")
    version_parser.add_argument("--timeout", type=int, default=3, help="Timeout (Default = 3).")
    version_parser.add_argument("--threads", type=int, default=10, help="Threads (Default = 10).")
    version_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    version_parser.set_defaults(func=version_console)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
    
