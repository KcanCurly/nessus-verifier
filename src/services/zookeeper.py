import subprocess
import re
import i18n
from src.utilities.utilities import error_handler, get_cves, get_default_context_execution2, get_latest_version, get_poc_from_cves
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class ZookeeperInfo():
    def __init__(self, host: str, version: str, info_disclosure: list[str]) -> None:
        self.host = host
        self.version = version
        self.info_disclosure = info_disclosure

class ZookeeperEnumServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("enum", "Run enumeration on zookeeper targets")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        print("Running metasploit zookeeper info disclosure module, there will be no progression bar")
        versions = {}
        info_vuln: dict[str, list[str]] = {}

        results: list[ZookeeperInfo] = get_default_context_execution2("Zookeeper Enum", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        for r in results:
            if r.version:
                if r.version not in versions:
                    versions[r.version] = []
                versions[r.version].append(r.host)
            if r.info_disclosure:
                info_vuln[r.host] = r.info_disclosure
                
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
            pocs = get_poc_from_cves(cve_list)
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

    def single(self, host, **kwargs):
        command = ["msfconsole", "-q", "-x", f"color false; use auxiliary/gather/zookeeper_info_disclosure; set RHOSTS {host.ip}; set RPORT {host.port}; set ConnectTimeout {self.timeout}; run; exit"]
        result = subprocess.run(command, text=True, capture_output=True)
        host_start = r"\[\*\] (.*)\s+ - Using a timeout of"
        zookeeper_version = r"zookeeper.version=(.*),"
        env = r"Environment:"
        host = ""
        info_vuln = []
        info = ZookeeperInfo(host, "", [])
        ver = ""
        
        for line in result.stdout.splitlines():
            try:
                matches = re.search(host_start, line)
                if matches:
                    host = matches.group(1)
                    continue
                
                matches = re.search(zookeeper_version, line)
                if matches:
                    ver = matches.group(1).split("-")[0]
                    continue
                    
                matches = re.search(env, line)
                if matches:
                    continue
                if "user.name" in line or "user.home" in line or "user.dir" in line or "os.name" in line or "os.arch" in line or "os.version" in line or "host.name" in line:
                    info_vuln.append(line)
                    
            except: pass

        return ZookeeperInfo(host, ver, info_vuln)


class ZookeeperServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("zookeeper")
        self.register_subservice(ZookeeperEnumServiceClass())
