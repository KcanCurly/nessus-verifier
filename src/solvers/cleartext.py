from ftplib import FTP
from ftplib import error_perm
from src.utilities.utilities import error_handler, get_default_context_execution, Host
from src.services.telnet import TelnetUsageSubServiceClass
import nmap
import requests
from src.solvers.solverclass import BaseSolverClass

class CleartextSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Cleartext Protocol Detected", 7)

    def solve(self, args):
        self._get_hosts(args) # type: ignore
        if not self.hosts:
            return
        if self.is_nv:
            hosts = self.subhosts.get("Unencrypted Telnet Server", [])
            if hosts: 
                TelnetUsageSubServiceClass().nv(hosts, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)
            hosts = self.subhosts.get("Basic Authentication Without HTTPS", [])
            if hosts: 
                self.solve_basic_http(hosts, args.threads, args.timeout, args.errors, args.verbose)
            hosts = self.subhosts.get("AMQP Cleartext Authentication", [])
            if hosts: 
                self.solve_amqp(hosts, args.threads, args.timeout, args.errors, args.verbose)
            hosts = self.subhosts.get("FTP Supports Cleartext Authentication", [])
            if hosts: 
                self.solve_ftp(hosts, args.threads, args.timeout, args.errors, args.verbose)


    @error_handler(["host"])
    def solver_amqp_single(self, host, timeout, errors, verbose):
        nm = nmap.PortScanner()

        nm.scan(host.ip, host.port, arguments=f'--script amqp-info')
        
        if host.ip in nm.all_hosts():
            nmap_host = nm[host.ip]
            if 'tcp' in nmap_host and int(host.port) in nmap_host['tcp']:
                tcp_info = nmap_host['tcp'][int(host.port)]
                if 'script' in tcp_info and 'amqp-info' in tcp_info['script']:
                    amqpinfo = tcp_info['script']['amqp-info']
                    for line in amqpinfo.splitlines():
                        if "mechanisms:" in line:
                            mech = line.split(":")[1].strip()
                            return (host, mech)
                                        
    
    @error_handler([])
    def solve_amqp(self, hosts, threads, timeout, errors, verbose):
        results: list[tuple[Host, str]] = get_default_context_execution("Cleartext Protocol Detected - AMQP Cleartext Authentication", threads, hosts, (self.solver_amqp_single, timeout, errors, verbose))
    
        if results:
            print("AMQP Cleartext Authentication Detected:")
            for r in results:
                print(f"{r[0]} - {r[1]}")

    @error_handler(["host"])
    def solve_basic_http_single(self, host, timeout, errors, verbose):
        response = requests.get(f"http://{host}", timeout=timeout)
        if response.status_code == 401 and "WWW-Authenticate" in response.headers:
            return host



    @error_handler([])
    def solve_basic_http(self, hosts, threads, timeout, errors, verbose):
        results = get_default_context_execution("Cleartext Protocol Detected - Basic Authentication Without HTTPS", threads, hosts, (self.solve_basic_http_single, timeout, errors, verbose))
        if results:
            print("Basic Authentication Without HTTPS Detected:")
            for value in results:
                print(f"{value}")

    @error_handler(["host"])
    def solve_ftp_single(self, host, timeout, errors, verbose):
        ftp = FTP()
        ftp.connect(host.ip, int(host.port), timeout=timeout)
        try:
            l = ftp.login()
            if "230" in l:
                return host

        except error_perm as e:
            if "530" in str(e):
                return host
        except Exception: pass

    @error_handler([])
    def solve_ftp(self, hosts, threads, timeout, errors, verbose):
        results = get_default_context_execution("Cleartext Protocol Detected - Basic Authentication Without HTTPS", threads, hosts, (self.solve_ftp_single, timeout, errors, verbose))
        
        if results:
            print("FTP Supporting Cleartext Authentication Detected:")
            for value in results:
                print(f"{value}")


    """
    # SMTP (TODO)
    try:
        hosts = scan.sub_hosts.get("54582")
        vuln = {}
        for host in hosts:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
            try:
                smtp = smtplib.SMTP(ip, int(port), timeout=5)
                smtp.ehlo()
                auths = smtp.esmtp_features.get("auth", "")
                print(f"Normal {auths}")
            except smtplib.SMTPServerDisconnected as t: # It could be that server requires TLS/SSL so we need to connect again with TLS
                try:
                    smtp = smtplib.SMTP_SSL(ip, int(port), timeout=5)
                    smtp.ehlo()
                    auths = smtp.esmtp_features.get("auth", "")
                    print(f"TLS {auths}")
                except Exception as e: print(e)
            except Exception as e: print(e)
    except Exception as e: print(e)
    """