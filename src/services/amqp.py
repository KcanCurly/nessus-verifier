import subprocess
import os
from src.utilities.utilities import error_handler, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import pika

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
        self.register_subservice(AMQPVersionSubServiceClass())