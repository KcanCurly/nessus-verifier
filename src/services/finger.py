import subprocess
import re
from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass


def users_nv(hosts: list[str], errors, verbose):
    ips = [line.split(":")[0] for line in hosts]
    result = ", ".join(ips)
    vuln = {}
    try:
        command = ["msfconsole", "-q", "-x", f"color false; use scanner/finger/finger_users; set RHOSTS {result}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        pattern = r"- (.*) Users found: (.*)"
        matches = re.findall(pattern, result.stdout)

        for m in matches:
            if m[0] not in vuln:
                vuln[m[0]] = []
            vuln[m[0]].append(m[1])
            
    except Exception as e: print(e)
    
    if len(vuln) > 0:
        print("Finger service user enumeration:")
        for k,v in vuln.items():
            print(f"    {k}:79 - {", ".join(v)}")
        

    
class ExampleSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("userenum", "Enumerates users")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        result = ", ".join(host.ip for host in hosts)

        vuln = {}
        try:
            command = ["msfconsole", "-q", "-x", f"color false; use scanner/finger/finger_users; set RHOSTS {result}; run; exit"]
            result = subprocess.run(command, text=True, capture_output=True)
            pattern = r"- (.*) Users found: (.*)"
            matches = re.findall(pattern, result.stdout)

            for m in matches:
                if m[0] not in vuln:
                    vuln[m[0]] = []
                vuln[m[0]].append(m[1])
                
        except Exception as e: print(e)
        
        if len(vuln) > 0:
            print("Finger service user enumeration:")
            for k,v in vuln.items():
                print(f"    {k}:79 - {", ".join(v)}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

class ExampleServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("finger")