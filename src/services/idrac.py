from src.utilities.utilities import get_default_context_execution2, error_handler, get_url_response
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class iDRAC_Version_Vuln_Data():
    def __init__(self, host: str, main_version:str, version: str):
        self.host = host
        self.main_version = main_version
        self.version = version

class IDRACVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks idrac version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[iDRAC_Version_Vuln_Data] = get_default_context_execution2("iDRAC Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        versions_9 = {}
        versions_8 = {}
        versions_7 = {}
        versions_unknown = {}
                    
        for r in results:
            if r.main_version == "9":
                if r.version not in versions_9:
                    versions_9[r.version] = set()
                versions_9[r.version].add(r.host)
            elif r.main_version == "8":
                if r.version not in versions_8:
                    versions_8[r.version] = set()
                versions_8[r.version].add(r.host)
            elif r.main_version == "7":
                if r.version not in versions_7:
                    versions_7[r.version] = set()
                versions_7[r.version].add(r.host)
            else:
                if r.version not in versions_unknown:
                    versions_unknown[r.version] = set()
                versions_unknown[r.version].add(r.host)

        if versions_9:
            self.print_output("Detected iDRAC 9 versions:")
            for key, value in versions_9.items():
                self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"    {v}")
                    
        if versions_8:
            self.print_output("Detected iDRAC 8 versions (EOL):")
            for key, value in versions_8.items():
                self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"    {v}")
                    
        if versions_7:
            self.print_output("Detected iDRAC 7 versions (EOL):")
            for key, value in versions_7.items():
                self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"    {v}")
                    
        if versions_unknown:
            self.print_output("Detected iDRAC versions:")
            for key, value in versions_unknown.items():
                self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        resp = get_url_response(f"{host}/sysmgmt/2015/bmc/info", self.timeout, False)
        if not resp:
            return
        if resp.status_code >= 300:
            resp = get_url_response(f"{host}/session?aimGetProp=fwVersion", self.timeout, False)
            if not resp:
                return
            if resp.status_code not in [200]: return
            version = resp.json()["aimGetProp"]["fwVersion"]
            resp = get_url_response(f"{host}/data?get=prodServerGen", self.timeout, False)
            if not resp:
                return
            if "12G" in resp.text: return iDRAC_Version_Vuln_Data(host, "7", version)
            elif "13G" in resp.text: return iDRAC_Version_Vuln_Data(host, "8", version)
            else: return iDRAC_Version_Vuln_Data(host, "N/A", version)
        version = resp.json()["Attributes"]["FwVer"]
        return iDRAC_Version_Vuln_Data(host, "9", version)

class IDRACServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("idrac")
        self.register_subservice(IDRACVersionSubServiceClass())