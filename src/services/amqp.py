import subprocess
import os
from src.utilities.utilities import error_handler, get_cves, get_hosts_from_file2, add_default_parser_arguments, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import pika
import nmap

class AMQPVersion2SubServiceClass(BaseSubServiceClass):
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
        
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                tcp_info = nmap_host['tcp'][int(port)]
                if 'script' in tcp_info and 'amqp' in tcp_info['script']:
                    amqp_info = tcp_info['script']['amqp-info']

                    # Parse the output to get product name and version
                    product_name = None
                    version_number = None

                    # Look for product and version in the output
                    for line in amqp_info.splitlines():
                        if "product:" in line:
                            product_name = line.split(":")[1].strip()
                        if "version:" in line:
                            version_number = line.split(":")[1].strip()

                    if product_name and version_number:
                        z = product_name + " " + version_number
                        return Version_Vuln_Host_Data(host, z)





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

        for host in hosts:
            try:
                connection = pika.BlockingConnection(pika.ConnectionParameters(host=host.ip, port=host.port, socket_timeout=timeout))
                channel = connection.channel()
                server_properties = channel.connection.server_properties
                if 'version' in server_properties:
                    v = server_properties['version']
                    if v not in vuln:
                        vuln[v] = set()
                    vuln[v].add(host.ip)

                connection.close()
            except Exception as e:
                if verbose:
                    print(f"Error connecting to {host.ip}: {e}")

        if vuln:
            print("Detected AMQP versions:")
            for version, hosts in vuln.items():
                print(f"Version {version}:")
                for v in hosts:
                    print(f"    {v}")
                


class AMQPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("amqp")
        self.register_subservice(AMQPVersion2SubServiceClass())