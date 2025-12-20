import subprocess
import re
import i18n
from src.utilities import utilities
from src.utilities.utilities import error_handler, get_cves, get_latest_version
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class ZookeeperEnumServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("enum", "Run enumeration on zookeeper targets")

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
                
        cpe = "cpe:2.3:a:apache:zookeeper:"
        eol_product_code = "zookeeper"
        cve_list = set()

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name='Apache Zookeeper'))
            for k,v in versions.items():
                k = k.strip()
                cves = []
                if self.should_print_cves:
                    cves = get_cves(cpe+k)
                    cve_list.update(cves)
                if cves:
                    self.print_output(f"Apache Zookeeper {k} ({",".join(cves)}):")
                else:
                    self.print_output(f"Apache Zookeeper {k}:")
                for a in v:
                    self.print_output(f"    {a}")
            
            if self.should_print_latest_version:
                vs = get_latest_version(eol_product_code)
                self.print_output(i18n.t('main.latest_version_title', name="Apache Zookeeper"))
                self.print_output(', '.join(vs or []))

        if self.should_print_poc and cve_list:
            pocs = utilities.get_poc_from_cves(cve_list)
            if pocs:
                self.print_output(i18n.t('main.poc_title'))
                for cve, poc_list in pocs.items():
                    self.print_output(f"{cve}:")
                    for poc in poc_list:
                        self.print_output(f"{poc}")
                    self.print_output("")
                    
        if info_vuln:
            self.print_output(i18n.t('main.zookeeper_information_disclosure'))
            for k,v in info_vuln.items():
                self.print_output(k)
                for a in v:
                    self.print_output(f"    {a}")


class ZookeeperServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("zookeeper")
        self.register_subservice(ZookeeperEnumServiceClass())
