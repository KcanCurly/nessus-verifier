import socket
import struct
import time

import i18n
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class TimeUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks Time protocol usage")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        

        results = get_default_context_execution2("Time Protocol Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if len(results):
            self.print_output(i18n.t('main.usage_title', name="Time"))
            for r in results:
                self.print_output(f"    {r}")

    @error_handler(["host"])
    def single(self, host, **kwargs):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)  # Set a timeout for the connection
            s.connect((host.ip, int(host.port)))  # Connect to the server
            
            # Receive the 4-byte binary time response
            data = s.recv(4)
            if len(data) != 4:
                if self.errors: print(f"Error for {host} - Invalid response length.")
                return
            
            # Unpack the 4-byte response as an unsigned integer
            server_time = struct.unpack("!I", data)[0]
            
            # Convert the server time to seconds since the Unix epoch
            unix_time = server_time - 2208988800  # Subtract Time Protocol epoch (1900) offset
            
            # Display the time in human-readable format
            return f"{host} - {time.ctime(unix_time)}"



class TimeServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("time")
        self.register_subservice(TimeUsageSubServiceClass())
