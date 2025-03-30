import socket
import struct
import time
from src.utilities.utilities import get_default_context_execution2
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
    
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class TimeUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks Time protocol usage")

    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        

        results: list[str] = get_default_context_execution2("Time Protocol Usage", threads, hosts, self.nv_single, timeout=timeout, errors=errors, verbose=verbose)

        if len(results):
            print("Time protocol detected:")
            for r in results:
                print(f"    {r}")


    def nv_single(self, host, **kwargs):
        timeout = kwargs.get("timeout", 5)
        errors = kwargs.get("errors", False)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)  # Set a timeout for the connection
                s.connect((host.ip, int(host.port)))  # Connect to the server
                
                # Receive the 4-byte binary time response
                data = s.recv(4)
                if len(data) != 4:
                    if errors: print(f"Error for {host} - Invalid response length.")
                    return
                
                # Unpack the 4-byte response as an unsigned integer
                server_time = struct.unpack("!I", data)[0]
                
                # Convert the server time to seconds since the Unix epoch
                unix_time = server_time - 2208988800  # Subtract Time Protocol epoch (1900) offset
                
                # Display the time in human-readable format
                return f"{host} - {time.ctime(unix_time)}"
        except Exception as e:
            if errors: print(f"Error for {host} - {e}")


class TimeServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("time")
        self.register_subservice(TimeUsageSubServiceClass())
