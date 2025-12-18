import re
import requests
import i18n
from src.utilities.utilities import error_handler, get_default_context_execution2, Version_Vuln_Host_Data, get_header_from_url, get_url_response
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass, VersionSubService
import requests
import jmxquery

class TomcatBruteforceSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Bruteforce")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        
        results = get_default_context_execution2(f"Tomcat Bruteforce", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="status", password="status")

        for r in results:
            self.print_output(f"{r[0]} is accessible by f{r[1]}:{r[2]}") # type: ignore

    @error_handler(["host"])
    def single(self, host, **kwargs):
        username=kwargs.get("username", "")
        password=kwargs.get("password", "")
        timeout=kwargs.get("timeout", 10)
        errors=kwargs.get("errors", False)
        verbose = kwargs.get("verbose", False)
        r = []

        # All these requires different built-in roles
        # It is possible 
        to_try = ["/manager/status", "/manager/html", "/manager/text/serverinfo"]

        for u in to_try:
            try:
                resp = requests.get(f"http://{host}{u}", auth=(username, password), allow_redirects=False)
                if resp.status_code in [200]:
                    r.append([(f"http://{host}{u}", username, password)])
            except Exception as e:
                pass

        CONNECTION_URL = f"service:jmx:rmi:///jndi/rmi://{host.ip}:{host.port}/jmxrmi"
        try:
            jmxConnection = jmxquery.JMXConnection(CONNECTION_URL)
            JMXQ = jmxquery.JMXQuery("Catalina:type=Manager,context=/servlets-examples", "maxActiveSessions")
            q = jmxConnection.query([JMXQ])
            for a in q:
                print(a.value)

        except Exception as e:
            print("Error", e)


class TomcatVersionSubServiceClass(VersionSubService):
    def __init__(self) -> None:
        super().__init__("version", "Checks version", [("Apache Tomcat", "apache-http-server")])

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

                self.print_single_version_result("Apache Tomcat", value, key, "cpe:2.3:a:apache:http_server:")

            self.print_latest_versions()
            self.print_pocs()



    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout=kwargs.get("timeout", 10)
        errors=kwargs.get("errors", False)
        verbose = kwargs.get("verbose", False)
        version_regex = r"Apache/(.*)"
        header = get_header_from_url(host, "Server", timeout, errors, verbose)
        if header:
            m = re.search(version_regex, header)
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)
        else:
            resp = get_url_response(host)
            version_regex = r"Apache Tomcat/(\d+\.\d+\.\d+)"
            m = re.search(version_regex, resp.text) # type: ignore
            if m:
                m = m.group(1)
                if " " in m:
                    m = m.split()[0]
                return Version_Vuln_Host_Data(host, m)



class TomcatServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("tomcat")

        self.register_subservice(TomcatVersionSubServiceClass())
        self.register_subservice(TomcatBruteforceSubServiceClass())