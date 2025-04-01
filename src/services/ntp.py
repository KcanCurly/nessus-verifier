import nmap
from src.utilities.utilities import Version_Vuln_List_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

def is_empty_or_spaces(s):
    return s.strip() == ""

class NTPMode6SubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("mode6", "Checks if mode 6 supported")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("NTP Mode 6 Usage", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print("NTP Mode 6 Enabled Hosts:")
            for r in results:
                print(r.host)
            print("NTP Mode 6 Data:")
            for r in results:
                print(f"{r.host}:")
                for v in r.version:
                    if is_empty_or_spaces(v): continue
                    print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        nm = nmap.PortScanner()

        nm.scan(hosts=ip, ports=port, arguments="--script=ntp-info -sU")
        for result in nm.all_hosts():
            if "udp" in nm[result] and int(port) in nm[result]["udp"]:
                ntp_script = nm[result]["udp"][int(port)].get("script", {})
                v = Version_Vuln_List_Host_Data(host, [])
                for key, value in ntp_script.items():
                    v.version.append(value)
                return v

class NTPMonlistSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("monlist", "Checks if monlist command is enabled")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("NTP Mode 6 Usage", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
                    
        if results:
            print("NTP monlist Enabled Hosts:")
            for r in results:
                print(r.host)
            print("NTP monlist Data:")
            for r in results:
                print(f"{r.host}:")
                for v in r.version:
                    if is_empty_or_spaces(v): continue
                    print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        nm = nmap.PortScanner()
        nm.scan(hosts=ip, ports=port, arguments="--script=ntp-monlist -sU")
        for result in nm.all_hosts():
            if "udp" in nm[result] and int(port) in nm[result]["udp"]:
                ntp_script = nm[result]["udp"][int(port)].get("script", {})
                v = Version_Vuln_List_Host_Data(host, [])
                for key, value in ntp_script.items():
                    v.version.append(value)
                return v



class NTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ntp")
        self.register_subservice(NTPMode6SubServiceClass())
        self.register_subservice(NTPMonlistSubServiceClass())