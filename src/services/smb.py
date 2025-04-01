import subprocess
import re
from impacket.smbconnection import SMBConnection
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import error_handler, get_default_context_execution2
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
        
class NullGuest_Vuln_Data():
    def __init__(self, host: str, null_files: dict[str, list[str]], guest_files: dict[str, list[str]]):
        self.host = host
        self.null_files = null_files
        self.guest_files = guest_files

class SMBNullGuestSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("nullguest", "Checks Null/Guest Share Access")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        null_vuln: dict[str, dict[str, list[str]]] = {}
        guest_vuln: dict[str, dict[str, list[str]]] = {}
        results_null: list[NullGuest_Vuln_Data] = get_default_context_execution2("Null Share Check", threads, hosts, self.single_null, timeout=timeout, errors=errors, verbose=verbose)
        results_guest: list[NullGuest_Vuln_Data] = get_default_context_execution2("Guest Share Check", threads, hosts, self.single_guest, timeout=timeout, errors=errors, verbose=verbose)
        results = results_null + results_guest
        
        for r in results:
            null_vuln[r.host] = {}
            guest_vuln[r.host] = {}
            for share, files in r.null_files.items():
                null_vuln[r.host][share] = files
            for share, files in r.guest_files.items():
                guest_vuln[r.host][share] = files
        
        if len(null_vuln) > 0:
            print("Null Accessble Shares Found:")
            for host, info in null_vuln.items():
                if len(info.items()) <= 0: continue
                print(f"{host}:")
                for share, files in info.items():
                    print(f"    {share}:")
                    for file in files:
                        print(f"        {file}")

        if len(guest_vuln) > 0:
            print("Guest Accessble Shares Found:")
            for host, info in guest_vuln.items():
                if len(info.items()) <= 0: continue
                print(f"{host}:")
                for share, files in info.items():
                    print(f"    {share}:")
                    for file in files:
                        print(f"        {file}")

    @error_handler(["host"])
    def single_guest(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        guest_vuln = {}

        # Get NetBIOS of the remote computer
        command = ["nmblookup", "-A", ip]
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
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
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        null_vuln = {}

        # Get NetBIOS of the remote computer
        command = ["nmblookup", "-A", ip]
        result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
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
        super().__init__("smbv1", "Checks SMBv1 usage")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results = get_default_context_execution2("SMB Signing Check", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print("SMB signing NOT enabled on hosts:")
            for v in results:
                print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        conn = SMBConnection(ip, ip, sess_port=int(port), timeout=timeout)
        if not conn._SMBConnection.is_signing_required(): 
            return host

class SMBv1SubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("smbv1", "Checks SMBv1 usage")

    @error_handler(["host"])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results = get_default_context_execution2("SMBv1 Check", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print("SMBv1 enabled on hosts:")
            for v in results:
                print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        SMBConnection(ip, ip, sess_port=int(port), timeout=timeout, preferredDialect="NT LM 0.12")
        return host

class SNMPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("smb")
        self.register_subservice(SMBv1SubServiceClass())
        self.register_subservice(SMBSignSubServiceClass())
        self.register_subservice(SMBNullGuestSubServiceClass())