import subprocess
from src.utilities.utilities import error_handler, get_default_context_execution2, Version_Vuln_List_Host_Data
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class RPC_Vuln_Data():
    def __init__(self, host: str, version: list[str]):
        self.host = host
        self.version = version

pipes = [
    "LSARPC:lsaquerysecobj",
    "SAMR:querydominfo",
    "SPOOLSS:getjob",
    "SRVSVC:srvinfo",
    "DFS:dfsversion",
    "WKSSVC:wkssvc_wkstagetinfo",
    "NTSVCS:ntsvcs_getversion",
    "DRSUAPI:dsgetdcinfo",
    "EVENTLOG:eventlog_loginfo",
    "WINREG:winreg_enumkey",
    "FSRVP:fss_get_sup_version",
    ]

class RPCUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("anonymous", "Check if anonymous rpc calls are possible")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("RPC Anonymous Access Check", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
    
        if results:
            self.print_output("Anonymous RPC pipes detected:")
            for r in results:
                self.print_output(r.host)
                for value in r.version:
                    self.print_output(f"    {value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        vul: list[str] = []

        for pipe in pipes:
            name, cmd = pipe.split(":")
            try:
                command = ["rpcclient", "-N", "-U", "","-c", cmd, ip]
                result = subprocess.run(command, text=True, capture_output=True)
                
                if "nt_status" not in result.stderr.lower() and "nt_status" not in result.stdout.lower(): # For some reason, errors are sometimes outted to stdout
                    vul.append(f"{name} - {result.stdout} - {result.stderr}")
            except:pass

        if vul:
            return Version_Vuln_List_Host_Data(host, vul) 

class RPCServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("rpc")
        self.register_subservice(RPCUsageSubServiceClass())