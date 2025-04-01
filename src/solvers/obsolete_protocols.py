import nmap
from src.solvers.solverclass import BaseSolverClass

class ObsoleteProtocolSolverClass(BaseSolverClass):
    def __init__(self, args) -> None:
        super().__init__("Obsolete Protocols", 18, args)

    def solve(self, args):
        self.hosts = self._get_hosts(args) # type: ignore
        if not self.hosts: 
            return

        vuln_echo = []
        vuln_discard = []
        vuln_daytime = []
        vuln_qotd = []
        vuln_chargen = []
        vuln_systat = []

        nm = nmap.PortScanner()
        for host in self.hosts:
            try:
                nm.scan(host.ip, host.port, arguments='-sV')
                
                if host.ip in nm.all_hosts():
                    nmap_host = nm[host.ip]
                    print(nmap_host)
                    if nmap_host.has_tcp(int(host.port)) and nmap_host['tcp'][int(host.port)]['state'] == 'open':
                        n = nmap_host['tcp'][int(host.port)]['name'].lower()
                        match n:
                            case 'echo':
                                vuln_echo.append(str(host))
                            case 'discard':
                                vuln_discard.append(str(host))
                            case 'daytime':
                                vuln_daytime.append(str(host))
                            case 'qotd':
                                vuln_qotd.append(str(host))
                            case 'chargen':
                                vuln_chargen.append(str(host))
                            case 'systat':
                                vuln_systat.append(str(host))
                                        
            except Exception:
                pass
        
        if len(vuln_echo) > 0:
            print("Echo Protocol Detected:")
            for value in vuln_echo:
                print(f"{value}")
                
        if len(vuln_discard) > 0:
            print("Discard Protocol Detected:")
            for value in vuln_discard:
                print(f"{value}")
                
        if len(vuln_daytime) > 0:
            print("Daytime Protocol Detected:")
            for value in vuln_daytime:
                print(f"{value}")
                
        if len(vuln_qotd) > 0:
            print("QOTD Protocol Detected:")
            for value in vuln_qotd:
                print(f"{value}")
                
        if len(vuln_chargen) > 0:
            print("Chargen Protocol Detected:")
            for value in vuln_chargen:
                print(f"{value}")
                
        if len(vuln_systat) > 0:
            print("Systat Protocol Detected:")
            for value in vuln_systat:
                print(f"{value}")
