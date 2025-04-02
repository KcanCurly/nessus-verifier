import subprocess
import re
from packaging.version import parse
from src.utilities.utilities import get_default_context_execution2, error_handler, get_cves, Host
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass


shodan_cves_to_skip = ["CVE-2008-3844", "CVE-2007-2768"]

protocol_pattern = r"Remote protocol version (.*),"
software_pattern = r"remote software version (.*)"
class Audit_Vuln_Data():
    def __init__(self, host: Host, is_vuln: bool, is_terrapin: bool, vuln_kex: list[str], vuln_mac: list[str], vuln_key: list[str], vuln_cipher):
        self.host = host
        self.is_vuln = is_vuln
        self.is_terrapin = is_terrapin
        self.vuln_kex = vuln_kex
        self.vuln_mac = vuln_mac
        self.vuln_key = vuln_key
        self.vuln_cipher = vuln_cipher

class SSH_Version_Vuln_Data():
    def __init__(self, host: Host, version: str, protocol: str):
        self.host = host
        self.version = version
        self.protocol = protocol

def remove_extra(input):
    input = input.replace("p1", "")
    input = input.replace("p2", "")
    return input

class SSHVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Run SSH version check on targets")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[SSH_Version_Vuln_Data] = get_default_context_execution2("SSH Version", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        protocol1 = []
        versions = {}
                    
        for r in results:
            if r.protocol and r.protocol != "2.0":
                protocol1.append(r.host)
            if r.version:
                r.version = r.version.split("_")[1]
                if r.version not in versions:
                    versions[r.version] = []
                versions[r.version].append(r.host)
                
        if len(protocol1) > 0:
            print("Protocol Version 1:")
            for p in protocol1:
                print(f"    {p}")
        
        if len(versions) > 0:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(remove_extra(x[0])), reverse=True)
            )
            print("SSH Versions:")
            for key, value in versions.items():
                key1 = key.replace("p1", "")
                key1 = key1.replace("p2", "")
                cves = get_cves(f"cpe:2.3:a:openbsd:openssh:{key1}", cves_to_skip=shodan_cves_to_skip)

                if cves: print(f"OpenSSH {key} ({", ".join(cves)}):")
                else: print(f"OpenSSH {key}:")
                for v in value:
                    print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port
        
        protocol = ""
        version = ""
        
        command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", ip]

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



class SSHAuditSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("", "Run ssh-audit on targets")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Audit_Vuln_Data] = get_default_context_execution2("SSH Audit", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
        
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


    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        vuln_kex = []
        vuln_mac = []
        vuln_key = []
        vuln_cipher = []
        # if verbose: console.print(f"Starting processing {host}")
        command = ["ssh-audit", "--skip-rate-test", "-t", str(timeout), str(host)]
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

        return Audit_Vuln_Data(host, is_vul, is_terrapin, vuln_kex, vuln_mac, vuln_key, vuln_cipher)



class SSHServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ssh")
        self.register_subservice(SSHAuditSubServiceClass())
        self.register_subservice(SSHVersionSubServiceClass())