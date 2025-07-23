import subprocess
import re
from impacket.smbconnection import SMBConnection # type: ignore
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import error_handler, get_default_context_execution2
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
        
class NullGuest_Vuln_Data():
    def __init__(self, host: str, null_files: dict[str, list[str]], guest_files: dict[str, list[str]]):
        self.host = host
        self.null_files = null_files
        self.guest_files = guest_files

class SMBOSVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("os-version", "Checks Version")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        r = r"\[\+\] (.*)\s+-.*likely  (.*)\)"

        print("Running nxc, there will be no progression bar")

        result = " ".join(h.ip for h in hosts)
        result2 = [h.ip for h in hosts]
        command = ["nxc", "smb"]
        command.extend(result2)

        result = subprocess.run(command, text=True, capture_output=True)

        obsoletes = ["Server 2012", "Windows 8.1", "Windows 7", "Windows 10"]
        obs = []

        for line in result.stdout.splitlines():
            try:
                parts = line.split()
                ip = parts[1]
                if ip == "nxc":
                    continue
                version = parts[5:-5]
                version = " ".join(version)
                if not "Windows" in version:
                    continue
                print(f"{ip} => {version}")
                if "Server 2012" in version:
                    obs.append(f"{ip} => {version}")
            except Exception:
                pass

        if obs:
            print("Obsolete Windows versions:")
            for o in obs:
                print(o)

        


class SMBNullGuestSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("nullguest", "Checks Null/Guest Share Access")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        null_vuln: dict[str, dict[str, list[str]]] = {}
        guest_vuln: dict[str, dict[str, list[str]]] = {}
        results_null: list[NullGuest_Vuln_Data] = get_default_context_execution2("Null Share Check", self.threads, hosts, self.single_null, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        results_guest: list[NullGuest_Vuln_Data] = get_default_context_execution2("Guest Share Check", self.threads, hosts, self.single_guest, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        results = results_null + results_guest
        
        for r in results:
            null_vuln[r.host] = {}
            guest_vuln[r.host] = {}
            for share, files in r.null_files.items():
                null_vuln[r.host][share] = files
            for share, files in r.guest_files.items():
                guest_vuln[r.host][share] = files
        written = False
        if null_vuln:
            for host, info in null_vuln.items():
                if len(info.items()) <= 0: continue
                if not written:
                    self.print_output("Null Accessble Shares Found:")
                    written = True
                self.print_output(f"{host}:")
                for share, files in info.items():
                    self.print_output(f"    {share}:")
                    for file in files:
                        self.print_output(f"        {file}")
        written = False
        if guest_vuln:
            for host, info in guest_vuln.items():
                if len(info.items()) <= 0: continue
                if not written:
                    self.print_output("Guest Accessble Shares Found:")
                    written = True
                self.print_output(f"{host}:")
                for share, files in info.items():
                    self.print_output(f"    {share}:")
                    for file in files:
                        self.print_output(f"        {file}")

    @error_handler(["host"])
    def single_guest(self, host, **kwargs):

        ip = host.ip
        port = host.port

        guest_vuln = {}

        # Get NetBIOS of the remote computer
        command = ["nmblookup", "-A", ip]
        result = subprocess.run(command, text=True, capture_output=True, timeout=self.timeout)
        netbios_re = r"\s+(.*)\s+<20>"
        
        s = re.search(netbios_re, result.stdout)
        if s:
            nbname = s.group()
            conn = pysmbconn.SMBConnection('guest', '', '', nbname, is_direct_tcp=True)
            if conn.connect(ip, 445): 
                shares = conn.listShares()
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        guest_vuln[share.name] = []
                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            guest_vuln[share.name].append(file.filename)
                    except Exception: pass
            return NullGuest_Vuln_Data(host, None, guest_vuln)
        
    @error_handler(["host"])
    def single_null(self, host, **kwargs):
        ip = host.ip
        port = host.port

        null_vuln = {}

        # Get NetBIOS of the remote computer
        command = ["nmblookup", "-A", ip]
        result = subprocess.run(command, text=True, capture_output=True, timeout=self.timeout)
        netbios_re = r"\s+(.*)\s+<20>"
        
        s = re.search(netbios_re, result.stdout)
        if s:
            nbname = s.group()
            conn = pysmbconn.SMBConnection('', '', '', nbname, is_direct_tcp=True)
            if conn.connect(ip, 445): 
                shares = conn.listShares()
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        null_vuln[share.name] = []
                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            null_vuln[share.name].append(file.filename)
                    except Exception: pass
            return NullGuest_Vuln_Data(host, null_vuln, None)

class SMBSignSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("sign", "Checks SMBv1 usage")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("SMB Signing Check", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("SMB signing NOT enabled on hosts:")
            for v in results:
                self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        conn = SMBConnection(ip, ip, sess_port=int(port), timeout=self.timeout)
        if not conn._SMBConnection.is_signing_required(): 
            return host

class SMBv1SubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("smbv1", "Checks SMBv1 usage")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("SMBv1 Check", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("SMBv1 enabled on hosts:")
            for v in results:
                self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        SMBConnection(ip, ip, sess_port=int(port), timeout=self.timeout, preferredDialect="NT LM 0.12")
        return host

class SMBServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("smb")
        self.register_subservice(SMBv1SubServiceClass())
        self.register_subservice(SMBSignSubServiceClass())
        self.register_subservice(SMBNullGuestSubServiceClass())
        self.register_subservice(SMBOSVersionSubServiceClass())