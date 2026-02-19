import re
import socket
import requests
import i18n
from utilities.utilities import error_handler, generate_random_string, get_default_context_execution2, Version_Vuln_Host_Data, get_header_from_url, get_url_response
from services.serviceclass import BaseServiceClass
from services.servicesubclass import BaseSubServiceClass, VersionSubService
import requests

class ApacheVersionSubServiceClass(VersionSubService):
    def __init__(self) -> None:
        super().__init__("version", "Checks version", [("Apache HTTP Web Server", "apache-http-server")])

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2(f"{self.products[0][0]} Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name=self.products[0][0]))
            
            for key, value in versions.items():

                self.print_single_version_result("Apache HTTP Web Server", value, key, "cpe:2.3:a:apache:http_server:")

            self.print_latest_versions()
            self.print_pocs()



    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout=kwargs.get("timeout", 10)
        errors=kwargs.get("errors", False)
        verbose = kwargs.get("verbose", False)
        version_regex = r"Apache/(\d+\.\d+\.\d+)"
        header = get_header_from_url(host, "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)

        resp = get_url_response(host)
        if resp is not None:
            m = re.search(version_regex, resp.text) # type: ignore
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)



class ApacheServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("apache")

        self.register_subservice(ApacheVersionSubServiceClass())
