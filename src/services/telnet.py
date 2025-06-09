import nmap
import socket
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class TelnetBannerSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("banner", "Banner Grab")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Telnet Banner Grab", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("Telnet Banners:")
            for r in results:
                self.print_output("=================================")
                self.print_output(r.host)
                self.print_output("=================================")
                self.print_output(r.version)
            
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
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("Telnet Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output("Telnet Usage Detected:")
            for value in results:
                self.print_output(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
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
