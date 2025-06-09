import nmap
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import error_handler

class ObsoleteProtocolSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Obsolete Protocols", 18)

    @error_handler([])
    def solve(self, args):
        self.process_args(args)

        if self.output:
            if not self.output.endswith("/"):
                self.output += "/"
            self.output += "obsolete_protocols.txt" 

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
        
        if vuln_echo:
            self.print_output("Echo Protocol Detected:")
            for value in vuln_echo:
                self.print_output(f"{value}")
                
        if vuln_discard:
            self.print_output("Discard Protocol Detected:")
            for value in vuln_discard:
                self.print_output(f"{value}")
                
        if vuln_daytime:
            self.print_output("Daytime Protocol Detected:")
            for value in vuln_daytime:
                self.print_output(f"{value}")
                
        if vuln_qotd:
            self.print_output("QOTD Protocol Detected:")
            for value in vuln_qotd:
                self.print_output(f"{value}")
                
        if vuln_chargen:
            self.print_output("Chargen Protocol Detected:")
            for value in vuln_chargen:
                self.print_output(f"{value}")
                
        if vuln_systat:
            self.print_output("Systat Protocol Detected:")
            for value in vuln_systat:
                self.print_output(f"{value}")
