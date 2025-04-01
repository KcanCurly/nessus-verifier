import socket
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc

class EchoUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        results = get_default_context_execution2("Echo Usage", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
        
        if results:
            print("Echo Usage Detected:")
            for value in results:
                print(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        try:
            ip, port = host.split(":")
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)  # Set timeout for connection
            
            # Connect to Systat service
            s.connect((ip, int(port)))
            s.sendall(b"pentest")
            response = b""  # Use bytes to handle binary data safely
            while True:
                chunk = s.recv(1024)  # Read in 1024-byte chunks
                if len(chunk) < 1:  # If empty, connection is closed
                    break
                response += chunk  # Append to response

            response = response.decode(errors="ignore")

            # Close the connection
            s.close()
            
            if response == "": 
                return host
        except Exception as e:
            if isinstance(response, bytes):
                response = response.decode(errors="ignore")
                if response == "pentest": 
                    return host
            if errors == 1: 
                print(f"Error for {host}: {e}")
            if errors == 2:
                print(f"Error for {host}: {e}")
                print_exc()



class EchoServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("echo")
        self.register_subservice(EchoUsageSubServiceClass())
