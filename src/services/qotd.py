import socket
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class QOTDBannerSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("banner", "Banner Grab")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("QOTD Banner Grab", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("QOTD Banners:")
            for r in results:
                self.print_output("=================================")
                self.print_output(r.host)
                self.print_output("=================================")
                self.print_output(r.version)
            
    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)  # Set timeout for connection
        
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

class QOTDUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("QOTD Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output("QOTD Usage Detected:")
            for value in results:
                self.print_output(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):

        ip = host.ip
        port = host.port

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)  # Set timeout for connection
        
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
        
        return host


class QOTDServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("qotd")
        self.register_subservice(QOTDUsageSubServiceClass())
        self.register_subservice(QOTDBannerSubServiceClass())
