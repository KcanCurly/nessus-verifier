import nmap
import socket
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class TelnetBannerSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("banner", "Banner Grab")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Telnet Banner Grab", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print("Telnet Banners:")
            for r in results:
                print("=================================")
                print(r.host)
                print("=================================")
                print(r.version)
            
    @error_handler(["host"])
    def single(self, host, timeout, errors, verbose):
        ip = host.ip
        port = host.port
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))

        response = b""  # Use bytes to handle binary data safely
        while True:
            chunk = s.recv(1024)  # Read in 1024-byte chunks
            if not chunk:  # If empty, connection is closed
                break
            response += chunk  # Append to response

        response = response.decode(errors="ignore")

        # Close the connection
        s.close()
        
        return Version_Vuln_Host_Data(host, response)

class TelnetUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage and prints product if possible")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        results = get_default_context_execution2("Telnet Usage", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
        
        if results:
            print("Telnet Usage Detected:")
            for value in results:
                print(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        nm = nmap.PortScanner()
        ip = host.ip
        port = host.port
        nm.scan(ip, port, arguments=f'-sV')
        
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'telnet' in nmap_host['tcp'][int(port)]['name'].lower():
                product = nmap_host['tcp'][int(port)].get("product", "Service not found")
                return f"{host}{f" - {product}" if product else ""}"


class TelnetServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("telnet")
        self.register_subservice(TelnetUsageSubServiceClass())
        self.register_subservice(TelnetBannerSubServiceClass())
