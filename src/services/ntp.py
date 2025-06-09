import nmap
from src.utilities.utilities import Version_Vuln_List_Host_Data, get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

def is_empty_or_spaces(s):
    return s.strip() == ""

class NTPMode6SubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("mode6", "Checks if mode 6 supported")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("NTP Mode 6 Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("NTP Mode 6 Enabled Hosts:")
            for r in results:
                self.print_output(r.host)
            self.print_output("NTP Mode 6 Data:")
            for r in results:
                self.print_output(f"{r.host}:")
                for v in r.version:
                    if is_empty_or_spaces(v): continue
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
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
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("NTP Monlist Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                    
        if results:
            self.print_output("NTP monlist Enabled Hosts:")
            for r in results:
                self.print_output(r.host)
            self.print_output("NTP monlist Data:")
            for r in results:
                self.print_output(f"{r.host}:")
                for v in r.version:
                    if is_empty_or_spaces(v): continue
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
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