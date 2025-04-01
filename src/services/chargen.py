import socket
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class ChargenBannerSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("banner", "Banner Grab")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Chargen Banner Grab", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print("Chargen Banners:")
            for r in results:
                print("=================================")
                print(r.host)
                print("=================================")
                print(r.version)
            
    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port
        # Create a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)  # Set timeout for connection
        
        # Connect to Systat service
        s.connect((ip, int(port)))

        response = s.recv(256)  # Use bytes to handle binary data safely
        response = response.decode(errors="ignore")

        # Close the connection
        s.close()
        
        return Version_Vuln_Host_Data(host, response)

class ChargenUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        results = get_default_context_execution2("Chargen Usage", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
        
        if results:
            print("Chargen Usage Detected:")
            for value in results:
                print(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port
        try:
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)  # Set timeout for connection
            
            # Connect to Systat service
            s.connect((ip, int(port)))

            response = s.recv(256)
            response = response.decode(errors="ignore")

            # Close the connection
            s.close()

            if response: 
                return host
        except Exception as e:
            if isinstance(response, bytes):
                response = response.decode(errors="ignore")
                year = response.split()[-1]
                if 1000 < int(year) < 9999: return host
            if errors: print(f"Error for {host}: {e}")


class ChargenServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("chargen")
        self.register_subservice(ChargenUsageSubServiceClass())
        self.register_subservice(ChargenBannerSubServiceClass())
