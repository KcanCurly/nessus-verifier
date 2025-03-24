import subprocess
import re
from src.utilities.utilities import get_cves, get_hosts_from_file, add_default_parser_arguments, get_default_context_execution
from packaging.version import parse

cve_dict = {
    
}

protocol_pattern = r"Remote protocol version (.*),"
software_pattern = r"remote software version (.*)"
class Audit_Vuln_Data():
    def __init__(self, host: str, is_vuln: bool, is_terrapin: bool, vuln_kex: list[str], vuln_mac: list[str], vuln_key: list[str], vuln_cipher):
        self.host = host
        self.is_vuln = is_vuln
        self.is_terrapin = is_terrapin
        self.vuln_kex = vuln_kex
        self.vuln_mac = vuln_mac
        self.vuln_key = vuln_key
        self.vuln_cipher = vuln_cipher

class SSH_Version_Vuln_Data():
    def __init__(self, host: str, version: str, protocol: str):
        self.host = host
        self.version = version
        self.protocol = protocol
        
def audit_single(host, timeout, errors, verbose):
    vuln_kex = []
    vuln_mac = []
    vuln_key = []
    vuln_cipher = []
    # if verbose: console.print(f"Starting processing {host}")
    command = ["ssh-audit", "--skip-rate-test", "-t", timeout, host]
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

        # if verbose: console.print(f"Successfully processed {host}: {"Terrapin," if is_terrapin else ""} {str(len(vuln_kex))} KEX, {str(len(vuln_mac))} MAC, {str(len(vuln_key))} HOST-KEY, {str(len(vuln_cipher))} CIPHER")
        
        return Audit_Vuln_Data(host, is_vul, is_terrapin, vuln_kex, vuln_mac, vuln_key, vuln_cipher)
    except Exception as e:
        if errors: print(f"Error for host {host}: {e}")

def audit_nv(hosts, threads, timeout, errors, verbose):
    results: list[Audit_Vuln_Data] = get_default_context_execution("SSH Audit", threads, hosts, (version_single, timeout, errors, verbose))
    
    vuln_kex = set()
    vuln_mac = set()
    vuln_key = set()
    vuln_cipher = set()
    vuln_hosts = set()
    vuln_terrapin = set()
   
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
        
    if len(vuln_mac) > 0:
        print("Vulnerable MAC algorithms:")
        for k in vuln_mac:
            print(f"    {k}")
            
    if len(vuln_key) > 0:
        print("Vulnerable Host-Key algorithms:")
        for k in vuln_key:
            print(f"    {k}")
    
    if len(vuln_cipher) > 0:
        print("Vulnerable Cipher algorithms:")
        for k in vuln_cipher:
            print(f"    {k}")
            
    if len(vuln_hosts) > 0:
        print("Vulnerable hosts:")
        for k in vuln_hosts:
            print(f"    {k}")
            
    if len(vuln_terrapin) > 0:
        print("Vulnerable Terraping hosts:")
        for k in vuln_terrapin:
            print(f"    {k}")

def audit_console(args):
    audit_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def version_single(host, timeout, errors, verbose):
    ip, port = host.split(":")
    
    protocol = ""
    version = ""
    
    command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", ip]
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

        return SSH_Version_Vuln_Data(host, version, protocol)
    except Exception as e:
        if errors: print(f"Error for host {host}: {e}")


def version_nv(hosts, threads, timeout, errors, verbose):
    results: list[SSH_Version_Vuln_Data] = get_default_context_execution("SSH Version", threads, hosts, (version_single, timeout, errors, verbose))

    protocol1 = []
    versions = {}
                 
    for r in results:
        if r.protocol and r.protocol != "2.0":
            protocol1.append(r.host)
        if r.version:
            r.version = r.version.split("_")[1]
            r.version = r.version.replace("p1", "")
            r.version = r.version.replace("p2", "")
            if r.version not in versions:
                versions[r.version] = []
            versions[r.version].append(r.host)
            
    if len(protocol1) > 0:
        print("Protocol Version 1:")
        for p in protocol1:
            print(f"    {p}")
    
    if len(versions) > 0:
        versions = dict(
            sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
        )
        print("SSH Versions:")
        for key, value in versions.items():
            cves = get_cves(f"cpe:2.3:a:openbsd:openssh:{key}")
            if cves: print(f"OpenSSH {key} ({", ".join(cves)}):")
            else: print(f"OpenSSH {key}:")
            for v in value:
                print(f"    {v}")

def version_console(args):
    version_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)
    
def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ssh")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_audit = subparsers.add_parser("audit", help="Run ssh-audit on targets")
    add_default_parser_arguments(parser_audit)
    parser_audit.set_defaults(func=audit_console)
    
    parser_version = subparsers.add_parser("version", help="Run SSH version check on targets")
    add_default_parser_arguments(parser_version)
    parser_version.set_defaults(func=version_console)
    