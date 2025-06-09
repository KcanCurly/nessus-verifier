import asyncio
import subprocess
import re
import asyncssh
from packaging.version import parse
from src.utilities.utilities import add_default_parser_arguments, get_default_context_execution2, error_handler, get_cves, Host, normalize_line_endings
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
        super().nv(hosts, kwargs=kwargs)

        results: list[SSH_Version_Vuln_Data] = get_default_context_execution2("SSH Version", self.threads, hosts, self.single)

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
                
        if protocol1:
            self.print_output("Protocol Version 1:")
            for p in protocol1:
                self.print_output(f"    {p}")
        
        if versions:
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(remove_extra(x[0])), reverse=True)
            )
            self.print_output("SSH Versions:")
            for key, value in versions.items():
                key1 = key.replace("p1", "")
                key1 = key1.replace("p2", "")
                cves = get_cves(f"cpe:2.3:a:openbsd:openssh:{key1}", cves_to_skip=shodan_cves_to_skip)

                if cves: self.print_output(f"OpenSSH {key} ({", ".join(cves)}):")
                else: self.print_output(f"OpenSSH {key}:")
                for v in value:
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        
        protocol = ""
        version = ""
        
        command = ["ssh", "-vvv", "-p", port, "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.timeout}", ip]

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

class SSHCommandSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("command", "Run command on targets")

    def helper_parse(self, subparsers):
        parser_enum = subparsers.add_parser(self.command_name, help = self.help_description)
        parser_enum.add_argument("target", type=str, help="File name or targets seperated by space, format is: 'host:port => username:password'")
        parser_enum.add_argument("command", type=str, help="Command to run")
        parser_enum.add_argument("--sudo", action="store_true", help="Run as sudo")
        add_default_parser_arguments(parser_enum, False)
        parser_enum.set_defaults(func=self.console)

    def console(self, args):
        asyncio.run(self.nv(args.target, args.command, args.sudo, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose))

    async def nv(self, hosts, command, sudo, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        lines = []
        with open(hosts, "r") as f:
            lines = f.readlines()

        try:
            async with asyncio.timeout(60): # 1 minute
                try:
                    async with asyncio.TaskGroup() as tg:
                        tasks = []
                        for entry in lines:
                            try:
                                entry = normalize_line_endings(entry.strip())
                                host, cred = entry.split(" => ")
                                ip, port = host.split(":")
                                username, password = cred.split(":")
                                tasks.append(tg.create_task(self.process_host(command, sudo, ip, port, username, password)))
                            except Exception as e:
                                print(f"Error parsing line '{entry.strip()}': {e}")
                        for task in asyncio.as_completed(tasks):
                            try:
                                await task
                            except Exception as e:
                                print(f"Task error: {e}")
                except Exception as e:
                    print(f"Task group error: {e}")
        except Exception as e:
            print(f"Timeout error: {e}")


    async def process_host(self, command, sudo, ip, port, username, password):
        try:
            async with await asyncssh.connect(ip, port=port, username=username, password=password, known_hosts=None, client_keys=None, keepalive_interval=10) as conn:
                if sudo:
                    command = f"echo '{password}' | sudo -S {command}"
                ans = await conn.run(command, check=True)
                if ans.stdout:
                    self.print_output("stdout ===========================")
                    self.print_output(f"{ip}:{port} - {username}:")
                    self.print_output(ans.stdout)
                if ans.stderr:
                    self.print_output("stderr ===========================")
                    self.print_output(f"{ip}:{port} - {username}:")
                    self.print_output(ans.stderr)

        except Exception as e:
            print(f"Error connecting to {ip}:{port} - {e}")

class SSHAuditSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("audit", "Run ssh-audit on targets")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Audit_Vuln_Data] = get_default_context_execution2("SSH Audit", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
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
        
        if vuln_kex:
            self.print_output("Vulnerable KEX algorithms:")
            for k in vuln_kex:
                self.print_output(f"    {k}")
            
        if vuln_mac:
            self.print_output("Vulnerable MAC algorithms:")
            for k in vuln_mac:
                self.print_output(f"    {k}")
                
        if vuln_key:
            self.print_output("Vulnerable Host-Key algorithms:")
            for k in vuln_key:
                self.print_output(f"    {k}")
        
        if vuln_cipher:
            self.print_output("Vulnerable Cipher algorithms:")
            for k in vuln_cipher:
                self.print_output(f"    {k}")
                
        if vuln_hosts:
            self.print_output("Vulnerable hosts:")
            for k in vuln_hosts:
                self.print_output(f"    {k}")
                
        if vuln_terrapin:
            self.print_output("Vulnerable Terrapin hosts:")
            for k in vuln_terrapin:
                self.print_output(f"    {k}")


    @error_handler(["host"])
    def single(self, host, **kwargs):
        vuln_kex = []
        vuln_mac = []
        vuln_key = []
        vuln_cipher = []
        # if verbose: console.print(f"Starting processing {host}")
        command = ["ssh-audit", "--skip-rate-test", "-t", str(self.timeout), str(host)]
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
        self.register_subservice(SSHCommandSubServiceClass())