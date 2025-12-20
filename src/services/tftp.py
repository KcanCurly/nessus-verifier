import subprocess
import re
import i18n
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from src.utilities.utilities import error_handler, get_default_context_execution2
import nmap

class TFTPBruteSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Run TFTP bruteforce on targets")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        nm = nmap.PortScanner()

        results = get_default_context_execution2(f"TFTP File Brute", self.threads, hosts, self.single, nm=nm, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
            
        if results:
            self.print_output(i18n.t('main.tftp_files_found'))
            #for k,v in results.items():
            #    self.print_output(f"{k}:")
            #    for a in v:
            #        self.print_output(f"    {a}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        nm:nmap.PortScanner = kwargs.get("nm") # type: ignore
        ip = host.ip
        port = host.port

        nm.scan(ip, port, arguments=f'-sU -sV --script tftp-enum')
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'udp' in nmap_host and int(port) in nmap_host['udp']:
                tcp_info = nmap_host['udp'][int(port)]
                print(tcp_info)
        
class TFTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("tftp")
        self.register_subservice(TFTPBruteSubServiceClass())
