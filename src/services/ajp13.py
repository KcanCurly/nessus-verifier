import re
import subprocess
from src.utilities.utilities import Host, error_handler, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE

class AJP13GhostcatSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("ghostcat", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        threads = kwargs.get("threads", DEFAULT_THREAD)

        r = r"\[\-\] (.*) - Unable to read file"
        print("Running metasploit ghostcat module, there will be no progression bar")

        ips = [h.ip for h in hosts]

        result = ", ".join(ips)
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/admin/http/tomcat_ghostcat; set RHOSTS {result}; set THREADS {threads}; run; exit"]

        result = subprocess.run(command, text=True, capture_output=True)
        matches = re.findall(r, result.stdout)

        print("Hosts:")
        print(hosts)
        print("Matches")
        # print(matches.__dict__)

        hosts2 = [h.str() for h in hosts]

        for m in matches:
            print("M")
            print(m)
            try:

                hosts2.remove(m[0])
            except Exception as e:pass

        if hosts2:
            self.print_output("Vulnerable to Ghostcat:")
            for host in hosts2:
                self.print_output(f"    {host}")



class AJP13ServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ajp13")
        self.register_subservice(AJP13GhostcatSubServiceClass())