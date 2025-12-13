from src.utilities.utilities import add_default_serviceclass_arguments, get_default_context_execution2, error_handler, get_cves, Host, normalize_line_endings, get_hosts_from_file, get_hosts_from_file2
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from concurrent.futures import ThreadPoolExecutor
from rich.live import Live
from rich.progress import TextColumn, Progress, BarColumn, TimeElapsedColumn
from rich.table import Column
from rich.console import Group
from rich.panel import Panel
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import requests

class HTTP401BruteSubServiceClass(BaseSubServiceClass):
    text_column1 = TextColumn("{task.fields[taskid]}", table_column=Column(ratio=1), style= "bold")
    text_column2 = TextColumn("{task.fields[status]}", table_column=Column(ratio=1), style= "dim")

    progress = Progress(
        text_column1, BarColumn(), text_column2, refresh_per_second= 1)

    overall_progress = Progress(
        TimeElapsedColumn(), BarColumn(), TextColumn("{task.completed}/{task.total}")
    )
    overall_task_id = overall_progress.add_task("", start=False)

    progress_group = Group(
        Panel(progress, title="401 Brute", expand=False),
        overall_progress,
    )

    def __init__(self) -> None:
        super().__init__("401brute", "Basic/Digest auth bruter")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("credential", type=str, help="File name or targets seperated by space, user:pass on each line")
        add_default_serviceclass_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file(args.target), creds=get_hosts_from_file(args.credential), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        creds = kwargs.get("creds", [])

        creds = kwargs.get("creds", [])
        threads = kwargs.get("threads", [])
        
        with Live(HTTP401BruteSubServiceClass.progress_group):
            HTTP401BruteSubServiceClass.overall_progress.update(HTTP401BruteSubServiceClass.overall_task_id, total=len(hosts))
            HTTP401BruteSubServiceClass.overall_progress.start_task(HTTP401BruteSubServiceClass.overall_task_id)
            with ThreadPoolExecutor(threads) as executor:
                for host in hosts:
                    task_id = HTTP401BruteSubServiceClass.progress.add_task("brute", start=False, taskid=f"{host}", status="status")
                    HTTP401BruteSubServiceClass.progress.update(task_id, visible=False)
                    executor.submit(self.single, task_id, host, creds=creds)

    @error_handler(["host"])
    def single(self, task_id, host, **kwargs):
        creds = kwargs.get("creds", [])
        cred_len = len(creds)

        try:
            HTTP401BruteSubServiceClass.progress.update(task_id, status=f"[yellow]Processing[/yellow]", total=cred_len, visible=True)
            HTTP401BruteSubServiceClass.progress.start_task(task_id)
            found_so_far = ""

            for i, cred in enumerate(creds):
                try:
                    username, password = cred.split(":")
                    resp = requests.get(host, verify=False, auth=(username, password), timeout=10)

                    if resp.status_code not in range(400, 600):
                        if not found_so_far: found_so_far = f"[green]Found -> [/green]"
                        else: found_so_far += "[green], [/green]"
                        found_so_far += f"[green]{username}:{password}[/green]"
                        self.print_output(f"{username}:{password}", normal_print=False)
                except Exception:
                    pass

                HTTP401BruteSubServiceClass.progress.update(task_id, status=f"[yellow]Trying Credentials {i+1}/{cred_len}[/yellow] {found_so_far}", advance=1)
                HTTP401BruteSubServiceClass.overall_progress.update(HTTP401BruteSubServiceClass.overall_task_id, advance=1)

            if not found_so_far:
                HTTP401BruteSubServiceClass.progress.update(task_id, visible=False)

        except Exception as e:
            HTTP401BruteSubServiceClass.progress.update(task_id, status=f"[red]Error {e}[/red]")


class HTTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("http")
        self.register_subservice(HTTP401BruteSubServiceClass())