from src.utilities.utilities import get_default_context_execution2, error_handler, get_url_response
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
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
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[iDRAC_Version_Vuln_Data] = get_default_context_execution2("iDRAC Version", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
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

        if len(versions_9) > 0:
            print("Detected iDRAC 9 versions:")
            for key, value in versions_9.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")
                    
        if len(versions_8) > 0:
            print("Detected iDRAC 8 versions (EOL):")
            for key, value in versions_8.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")
                    
        if len(versions_7) > 0:
            print("Detected iDRAC 7 versions (EOL):")
            for key, value in versions_7.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")
                    
        if len(versions_unknown) > 0:
            print("Detected iDRAC versions:")
            for key, value in versions_unknown.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        resp = get_url_response(f"{host}/sysmgmt/2015/bmc/info", timeout, False)
        if not resp:
            return
        if resp.status_code >= 300:
            resp = get_url_response(f"{host}/session?aimGetProp=fwVersion", timeout, False)
            if not resp:
                return
            if resp.status_code not in [200]: return
            version = resp.json()["aimGetProp"]["fwVersion"]
            resp = get_url_response(f"{host}/data?get=prodServerGen", timeout, False)
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