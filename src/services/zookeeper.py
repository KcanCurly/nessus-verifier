import subprocess
import re

import i18n
from src.utilities.utilities import error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class ZookeeperEnumServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("zookeeper", "Run enumeration on zookeeper targets")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        print("Running metasploit zookeeper info disclosure module with forcing 1 thread, there will be no progression bar")
        versions = {}
        info_vuln: dict[str, list[str]] = {}

        result = ", ".join(host.ip for host in hosts)


        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/gather/zookeeper_info_disclosure; set RHOSTS {result}; set ConnectTimeout {self.timeout}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        host_start = r"\[\*\] (.*)\s+ - Using a timeout of"
        zookeeper_version = r"zookeeper.version=(.*),"
        env = r"Environment:"
        host = ""
        
        for line in result.stdout.splitlines():
            try:
                matches = re.search(host_start, line)
                if matches:
                    host = matches.group(1)
                    continue
                
                matches = re.search(zookeeper_version, line)
                if matches:
                    ver = matches.group(1).split("-")[0]
                    if ver not in versions:
                        versions[ver] = set()
                    versions[ver].add(host)
                    continue
                    
                matches = re.search(env, line)
                if matches:
                    info_vuln[host] = []
                    continue
                if "user.name" in line or "user.home" in line or "user.dir" in line or "os.name" in line or "os.arch" in line or "os.version" in line or "host.name" in line:
                    info_vuln[host].append(line)
                    
            except: pass
                


        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name='Apache Zookeeper'))
            for k,v in versions.items():
                self.print_output(f"Apache Zookeeper {k.strip()}:")
                for a in v:
                    self.print_output(f"    {a}")
                    
        if info_vuln:
            self.print_output(i18n.t('main.zookeeper_information_disclosure'))
            for k,v in info_vuln.items():
                self.print_output(f"{k}:")
                for a in v:
                    self.print_output(f"    {a}")


class ZookeeperServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("zookeeper")
        self.register_subservice(ZookeeperEnumServiceClass())
