import socket

import i18n
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc

class EchoUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("Echo Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output(i18n.t('main.usage_title', name='Echo'))
            for value in results:
                self.print_output(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        try:
            ip, port = host.split(":")
            # Create a socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)  # Set timeout for connection
            
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
            if self.errors == 1: 
                print(f"Error for {host}: {e}")
            if self.errors == 2:
                print(f"Error for {host}: {e}")
                print_exc()



class EchoServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("echo")
        self.register_subservice(EchoUsageSubServiceClass())
