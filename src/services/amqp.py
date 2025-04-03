import subprocess
import os
from src.utilities.utilities import error_handler, get_cves, get_hosts_from_file2, add_default_parser_arguments, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import pika
import nmap

class AMQPVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        vuln = {}

        nm = nmap.PortScanner()
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("AMQP Version", threads, hosts, self.single, nm=nm, timeout=timeout, errors=errors, verbose=verbose)

        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            print("Detected AMQP Versions:")
            
            for key, value in versions.items():
                extra, pure_version = key.rsplit(" ", 1)

                cpe = ""
                cves = []
                if "rabbitmq" in key.lower():
                    cpe = f"cpe:2.3:a:vmware:rabbitmq:{pure_version}"
                if cpe: 
                    cves = get_cves(cpe)
                if cves: 
                    print(f"{extra} {pure_version} ({", ".join(cves)}):")
                else:
                    print(f"{extra} {pure_version}:")

                for v in value:
                    print(f"    {v}")




    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        nm:nmap.PortScanner = kwargs.get("nm") # type: ignore
        ip = host.ip
        port = host.port

        nm.scan(ip, port, arguments=f'--script amqp-info')
        print(1)
        if ip in nm.all_hosts():
            print(2)
            nmap_host = nm[ip]
            if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                print(3)
                tcp_info = nmap_host['tcp'][int(port)]
                product_name = None
                version_number = None
                product_name = tcp_info['product']
                version_number = tcp_info['version']
                z = product_name + " " + version_number
                return Version_Vuln_Host_Data(host, z)



class AMQPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("amqp")
        self.register_subservice(AMQPVersionSubServiceClass())