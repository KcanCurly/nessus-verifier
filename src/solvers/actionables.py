from src.utilities.utilities import find_scan
from src.modules.nv_parse import GroupNessusScanOutput
from src.utilities import logger
from src.solvers.solverclass import BaseSolverClass

class ActionablesSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("Actionables", 0, args)

    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            hosts = self.subhosts.get("Apache Solr Config API Velocity Template RCE (Direct Check)", [])
            if hosts:
                print("metasploit: use exploit/multi/http/solr_velocity_rce")
                for host in hosts:
                    print(host)
            hosts = self.subhosts.get("VMware vCenter Server Virtual SAN Health Check plug-in RCE (CVE-2021-21985) (direct check)", [])
            if hosts:
                print("metasploit: use exploit/linux/http/vmware_vcenter_vsan_health_rce")
                for host in hosts:
                    print(host)

