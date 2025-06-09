import nmap
from src.utilities.utilities import Version_Vuln_List_Host_Data, get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

def is_empty_or_spaces(s):
    return s.strip() == ""

class MDNSDiscoverySubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("discovery", "Runs nmap mdns discovery script")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("MDNS DNS Discovery", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                    
        if results:
            self.print_output("mDNS Enabled Hosts:")
            for r in results:
                self.print_output(r.host)
            self.print_output("mDNS Service Discovery:")
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
        nm.scan(hosts=ip, ports=port, arguments="--script=dns-service-discovery -sU")
        for result in nm.all_hosts():
            if "udp" in nm[result] and int(port) in nm[result]["udp"]:
                ntp_script = nm[result]["udp"][int(port)].get("script", {})
                v = Version_Vuln_List_Host_Data(host, [])
                if len(ntp_script.items()):
                    for key, value in ntp_script.items():
                        if not value or not key:
                            continue
                        v.version.append(value)
                    return v

class MDNSServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mdns")
        self.register_subservice(MDNSDiscoverySubServiceClass())