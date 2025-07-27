from ftplib import FTP
from ftplib import Error
from ftplib import FTP_TLS
from src.utilities.utilities import error_handler, get_hosts_from_file, get_hosts_from_file2, get_default_context_execution2, add_default_parser_arguments, Host
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

        results: list[FTP_Brute_Vuln_Data] = get_default_context_execution2("FTP Brute", self.threads, hosts, self.single, creds=creds, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output("FTP Credentials Found on Hosts:")
            for a in results:
                self.print_output(f"    {a.host}{" [TLS]" if a.is_TLS else ""} - {", ".join(a.creds)}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        creds = kwargs.get("creds", [])
        ip = host.ip
        port = host.port

        vuln = FTP_Brute_Vuln_Data(host, False, [])

        for cred in creds:
            try:
                username, password = cred.split(":")
                ftp = FTP()
                ftp.connect(ip, int(port), timeout=self.timeout)
                l = ftp.login(username, password)
                if "230" in l:
                    vuln.creds.append(f"{username}:{password}")
                    ftp.close()
            except Error:
                try:
                    ftp = FTP_TLS()
                    ftp.connect(ip, int(port), timeout=self.timeout)
                    l = ftp.login(username, password)
                    if "230" in l:
                        vuln.is_TLS = True
                        vuln.creds.append(f"{username}:{password}")
                        ftp.close()
                    else: 
                        ftp.close()
                except Exception:
                    ftp.close()

        if vuln.creds: 
            return vuln

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