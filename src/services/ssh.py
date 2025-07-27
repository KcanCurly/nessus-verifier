import asyncio
import subprocess
import re
import asyncssh
from packaging.version import parse
from src.utilities.utilities import add_default_parser_arguments, get_default_context_execution2, error_handler, get_cves, Host, normalize_line_endings, get_hosts_from_file, get_hosts_from_file2
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import argparse
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from rich.live import Live
from rich.progress import TextColumn, Progress, BarColumn, TimeElapsedColumn
from rich.table import Column
from rich.console import Group
from rich.panel import Panel


shodan_cves_to_skip = ["CVE-2008-3844", "CVE-2007-2768"]

protocol_pattern = r"Remote protocol version (.*),"
software_pattern = r"remote software version (.*)"

lock = threading.Lock()  # Lock for writing to the result file

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

class SSHBruteSubServiceClass(BaseSubServiceClass):

    text_column1 = TextColumn("{task.fields[taskid]}", table_column=Column(ratio=1), style= "bold")
    text_column2 = TextColumn("{task.fields[status]}", table_column=Column(ratio=1), style= "dim")

    progress = Progress(
        text_column1, BarColumn(), text_column2, refresh_per_second= 1)

    overall_progress = Progress(
        TimeElapsedColumn(), BarColumn(), TextColumn("{task.completed}/{task.total}")
    )
    overall_task_id = overall_progress.add_task("", start=False)

    progress_group = Group(
        Panel(progress, title="SSHWHIRL", expand=False),
        overall_progress,
    )
    
    def __init__(self) -> None:
        super().__init__("brute", "Run SSH version check on targets")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("credential", type=str, help="File name or targets seperated by space, user:pass on each line")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), creds=get_hosts_from_file(args.credential), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        creds = kwargs.get("creds", [])
        threads = kwargs.get("threads", [])


        
        with Live(SSHBruteSubServiceClass.progress_group):
            SSHBruteSubServiceClass.overall_progress.update(SSHBruteSubServiceClass.overall_task_id, total=len(hosts)*len(creds))
            SSHBruteSubServiceClass.overall_progress.start_task(SSHBruteSubServiceClass.overall_task_id)
            with ThreadPoolExecutor(threads) as executor:
                for host in hosts:
                    task_id = SSHBruteSubServiceClass.progress.add_task("brute", start=False, taskid=f"{host[0]}:{host[1]}", status="status")
                    SSHBruteSubServiceClass.progress.update(task_id, visible=False)
                    executor.submit(self.single, task_id, host[0], host[1], creds)



    @error_handler(["host"])
    def single(self, task_id, ip, port, creds):
        cred_len = len(creds)
        try:
            SSHBruteSubServiceClass.progress.update(task_id, status=f"[yellow]Processing[/yellow]", total=cred_len, visible=True)
            SSHBruteSubServiceClass.progress.start_task(task_id)
            if not self.pre_check(task_id, ip, port):
                SSHBruteSubServiceClass.progress.update(task_id, status=f"[red]Precheck Failed[/red]", visible=False)
                SSHBruteSubServiceClass.overall_progress.update(SSHBruteSubServiceClass.overall_task_id, advance=1)
                return
            else:
                found_so_far = ""
                for i, (username, password) in enumerate(creds):
                    message = self.check_ssh_connection(task_id, ip, port, username, password)
                    if message and message.startswith("[+]"):
                        if not found_so_far: found_so_far = f"[green]Found -> [/green]"
                        else: found_so_far += "[green], [/green]"
                        found_so_far += f"[green]{username}:{password}[/green]"
                        self.print_output(message[4:])
                        
                    SSHBruteSubServiceClass.progress.update(task_id, status=f"[yellow]Trying Credentials {i+1}/{cred_len}[/yellow] {found_so_far}", advance=1)
                    SSHBruteSubServiceClass.overall_progress.update(SSHBruteSubServiceClass.overall_task_id, advance=1)
                if not found_so_far:
                    SSHBruteSubServiceClass.progress.update(task_id, visible=False)
            
        except Exception as e:
            SSHBruteSubServiceClass.progress.update(task_id, status=f"[red]Error {e}[/red]")

    def pre_check(self, task_id, host, port):
        try:
            # Construct the sshpass command to pass the password and run the ssh command
            command = [
                "sshpass", 
                "-p", "a",  # Password for SSH
                "ssh", 
                "-o", f"ConnectTimeout={10}",  # Set the connection timeout
                "-o", "StrictHostKeyChecking=no",  # Automatically accept host keys
                "-o", "PasswordAuthentication=yes",  # Ensure password authentication is used
                "-p", port,  # Port for SSH connection
                f"a@{host}",  # Username and host
                "exit"  # Simple command to execute (does nothing)
            ]

            # Run the command using subprocess
            result = subprocess.run(command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Check if the ssh command was successful
            if result.returncode == 255:
                return False
            return True

        except Exception as e:
            return False
        
    def check_ssh_connection(self, task_id, host, port, username, password, retry_count=0):
        """
        Check if SSH connection is successful using the system's sshpass and ssh command.
        Supports retrying after a connection reset.
        """

        try:
            # Construct the sshpass command to pass the password and run the ssh command
            command = [
                "sshpass", 
                "-p", password,  # Password for SSH
                "ssh", 
                "-o", f"ConnectTimeout={10}",  # Set the connection timeout
                "-o", "StrictHostKeyChecking=no",  # Automatically accept host keys
                "-o", "PasswordAuthentication=yes",  # Ensure password authentication is used
                "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256",
                "-o", "Ciphers=+aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc",
                "-o", "MACs=+hmac-sha1,hmac-md5,hmac-sha2-256,hmac-sha2-512",
                "-p", port,  # Port for SSH connection
                f"{username}@{host}",  # Username and host
                "exit"  # Simple command to execute (does nothing)
            ]

            # Run the command using subprocess
            result = subprocess.run(command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Check if the ssh command was successful
            if result.returncode == 0:
                return f"[+] {host}:{port} => {username}:{password}"
            elif result.returncode == 255:  # SSH connection reset or error
                if retry_count < 3:
                    wait_time = [20, 40, 60][retry_count]  # Retry times (20, 40, 60 seconds)
                    time.sleep(wait_time)  # Wait before retrying
                    return self.check_ssh_connection(task_id, host, port, username, password, retry_count + 1)
                else:
                    return f"[!] Maximum retries reached for {host} ({username}:{password})"
            else:
                return None  # Return None if authentication failed for another reason

        except Exception as e:
            print(e)
            return f"[!] Error connecting to {host} ({username}:{password}): {e}"

        


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
                sorted(versions.items(), key=lambda x: x[0], reverse=True)
            )
            self.print_output("SSH Versions:")
            for key, value in versions.items():
                major = key
                minor = ""
                p_index = key.find('p')
                if p_index != -1:
                    major = key[:p_index]
                    minor  = key[p_index:]

                cves = get_cves(f"cpe:2.3:a:openbsd:openssh:{major}{f":{minor}" if minor else ''}", cves_to_skip=shodan_cves_to_skip)

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