from ftplib import FTP
from ftplib import Error
from ftplib import FTP_TLS
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
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import nmap

class FTP_Anon_Vuln_Data():
    def __init__(self, host: Host, is_TLS: bool):
        self.host = host
        self.is_TLS = is_TLS
        
class FTP_Brute_Vuln_Data():
    def __init__(self, host: str, is_TLS: bool, creds: list[str]):
        self.host = host
        self.is_TLS = is_TLS
        self.creds = creds

class FTPBruteSubServiceClass(BaseSubServiceClass):
    text_column1 = TextColumn("{task.fields[taskid]}", table_column=Column(ratio=1), style= "bold")
    text_column2 = TextColumn("{task.fields[status]}", table_column=Column(ratio=1), style= "dim")

    progress = Progress(
        text_column1, BarColumn(), text_column2, refresh_per_second= 1)

    overall_progress = Progress(
        TimeElapsedColumn(), BarColumn(), TextColumn("{task.completed}/{task.total}")
    )
    overall_task_id = overall_progress.add_task("", start=False)

    progress_group = Group(
        Panel(progress, title="FTP Brute", expand=False),
        overall_progress,
    )

    def __init__(self) -> None:
        super().__init__("brute", "Brute login")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("credential", type=str, help="File name or targets seperated by space, user:pass on each line")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), creds=get_hosts_from_file(args.credential), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        creds = kwargs.get("creds", [])

        creds = kwargs.get("creds", [])
        threads = kwargs.get("threads", [])
        
        with Live(FTPBruteSubServiceClass.progress_group):
            FTPBruteSubServiceClass.overall_progress.update(FTPBruteSubServiceClass.overall_task_id, total=len(hosts)*len(creds))
            FTPBruteSubServiceClass.overall_progress.start_task(FTPBruteSubServiceClass.overall_task_id)
            with ThreadPoolExecutor(threads) as executor:
                for host in hosts:
                    task_id = FTPBruteSubServiceClass.progress.add_task("brute", start=False, taskid=f"{host.ip}:{host.port}", status="status")
                    FTPBruteSubServiceClass.progress.update(task_id, visible=False)
                    executor.submit(self.single, task_id, host, creds=creds)

    @error_handler(["host"])
    def single(self, task_id, host, **kwargs):
        creds = kwargs.get("creds", [])
        ip = host.ip
        port = host.port
        cred_len = len(creds)

        vuln = FTP_Brute_Vuln_Data(host, False, [])

        try:
            FTPBruteSubServiceClass.progress.update(task_id, status=f"[yellow]Processing[/yellow]", total=cred_len, visible=True)
            FTPBruteSubServiceClass.progress.start_task(task_id)
            found_so_far = ""

            for i, cred in enumerate(creds):
                try:
                    username, password = cred.split(":")
                    ftp = FTP()
                    ftp.connect(ip, int(port), timeout=self.timeout)
                    l = ftp.login(username, password)
                    if "230" in l:
                        if not found_so_far: found_so_far = f"[green]Found -> [/green]"
                        else: found_so_far += "[green], [/green]"
                        found_so_far += f"[green]{username}:{password}[/green]"
                        self.print_output(f"{username}:{password}", normal_print=False)
                        ftp.close()
                except Error:
                    try:
                        ftp = FTP_TLS()
                        ftp.connect(ip, int(port), timeout=self.timeout)
                        l = ftp.login(username, password)
                        if "230" in l:
                            if not found_so_far: found_so_far = f"[green]Found -> [/green]"
                            else: found_so_far += "[green], [/green]"
                            found_so_far += f"[green]{username}:{password} (TLS)[/green]"

                            self.print_output(f"{username}:{password} (TLS)", normal_print=False)

                            ftp.close()
                        else: 
                            ftp.close()
                    except Exception:
                        ftp.close()

                FTPBruteSubServiceClass.progress.update(task_id, status=f"[yellow]Trying Credentials {i+1}/{cred_len}[/yellow] {found_so_far}", advance=1)
                FTPBruteSubServiceClass.overall_progress.update(FTPBruteSubServiceClass.overall_task_id, advance=1)

            if not found_so_far:
                FTPBruteSubServiceClass.progress.update(task_id, visible=False)

        except Exception as e:
            FTPBruteSubServiceClass.progress.update(task_id, status=f"[red]Error {e}[/red]")


class FTPAnonSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("anonymous", "Checks if anonymous login is possible")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[FTP_Anon_Vuln_Data] = get_default_context_execution2("FTP Anon", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                        
        if results:
            self.print_output("FTP Anonymous Access on Hosts:")               
            for a in results:
                self.print_output(f"    {a.host}{" [TLS]" if a.is_TLS else ""}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        ftp = FTP()
        ftp.connect(ip, int(port), timeout=self.timeout)
        try:
            l = ftp.login()
            if "230" in l:
                return FTP_Anon_Vuln_Data(host, False)

        except Error as e:
            ftp = FTP_TLS()
            ftp.connect(ip, int(port), timeout=self.timeout)
            l = ftp.login()
            if "230" in l:
                return FTP_Anon_Vuln_Data(host, True)
            
class FTPVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("FTP Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                        
        if results:
            self.print_output("FTP Version:")               
            for a in results:
                self.print_output(f"    {a}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        try:
            nm = nmap.PortScanner()
            ip = host.ip
            port = host.port
            nm.scan(ip, port, arguments=f'-sV')

            for host in nm.all_hosts():
                nmap_host = nm[host]
                if 'ftp' in nmap_host['tcp'][int(port)]['name'].lower():
                    product = nmap_host['tcp'][int(port)].get("product", "Service not found")
                    version = nmap_host['tcp'][int(port)].get('version', '')
                    return f"{host}:{port} - {product} {version}"
        except Exception as e:
            print(f"Exception: {e}")

class FTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ftp")
        self.register_subservice(FTPAnonSubServiceClass())
        self.register_subservice(FTPBruteSubServiceClass())
        self.register_subservice(FTPVersionSubServiceClass())