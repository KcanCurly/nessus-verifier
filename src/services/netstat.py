import socket
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc

class NetstatBannerSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("banner", "Banner Grab")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Netstat Banner Grab", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("Netstat Banners:")
            for r in results:
                self.print_output("=================================")
                self.print_output(r.host)
                self.print_output("=================================")
                self.print_output(r.version)
            
    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        try:

            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)  # Set timeout for connection
            
            # Connect to Systat service
            s.connect((ip, int(port)))

            response = b""  # Use bytes to handle binary data safely
            while True:
                chunk = s.recv(4096)  # Read in 1024-byte chunks
                if not chunk:  # If empty, connection is closed
                    break
                response += chunk  # Append to response

            response = response.decode(errors="ignore")

            # Close the connection
            s.close()
            
            if "Local Address" in response and "Proto" in response and "State" in response: 
                return Version_Vuln_Host_Data(host, response)
        except Exception as e:
            if isinstance(response, bytes):
                response = response.decode(errors="ignore")
                if "Local Address" in response and "Proto" in response and "State" in response: 
                    return Version_Vuln_Host_Data(host, response)
                if self.errors: 
                    print(f"Error for {host}: {e}")

class NetstatUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        results = get_default_context_execution2("Netstat Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            print("Netstat Usage Detected:")
            for value in results:
                print(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)  # Set timeout for connection
            
            # Connect to Systat service
            s.connect((ip, int(port)))

            response = b""  # Use bytes to handle binary data safely
            while True:
                chunk = s.recv(4096)  # Read in 1024-byte chunks
                if not chunk:  # If empty, connection is closed
                    break
                response += chunk  # Append to response

            response = response.decode(errors="ignore")

            # Close the connection
            s.close()
            
            if "Local Address" in response and "Proto" in response and "State" in response: 
                return host
        except Exception as e:
            if isinstance(response, bytes):
                response = response.decode(errors="ignore")
                if "Local Address" in response and "Proto" in response and "State" in response: 
                    return host
            if self.errors == 1: 
                print(f"Error for {host}: {e}")
            if self.errors == 2:
                print(f"Error for {host}: {e}")
                print_exc()


class NetstatServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("netstat")
        self.register_subservice(NetstatUsageSubServiceClass())
        self.register_subservice(NetstatBannerSubServiceClass())
