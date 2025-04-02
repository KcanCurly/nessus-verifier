import subprocess
import re
import ssl
import socket
import tomllib
from src.utilities.utilities import find_scan, add_default_solver_parser_arguments, add_default_parser_arguments, get_default_context_execution, Host
from src.modules.nv_parse import GroupNessusScanOutput
from src.solvers.solverclass import BaseSolverClass

class TLS_Vuln_Data():
    def __init__(self, host: Host, weak_versions: list[str], weak_ciphers: list[str], weak_bits: list[str], is_wrong_hostname: bool, is_cert_expired: str):
        self.host = host
        self.weak_versions = weak_versions
        self.weak_ciphers = weak_ciphers
        self.weak_bits = weak_bits
        self.is_wrong_hostname = is_wrong_hostname
        self.is_cert_expired = is_cert_expired

class TLSSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("TLS Misconfigurations", 1)

    def solve(self, args):
        super().solve(args)
        if not self.hosts: 
            return
        self.tls_nv(self.hosts, args.allow_white_ciphers, args.threads, args.timeout, args.errors, args.verbose)




    def get_default_config(self):
        return """
    ["1"]
    allow_white_ciphers = true
    """

    def helper_parse(self, subparser):
        parser_task1 = subparser.add_parser(str(1), help="TLS Misconfigurations")
        add_default_solver_parser_arguments(parser_task1)
        parser_task1.add_argument("--allow-white-ciphers", action="store_true", required=False, help="White named ciphers are fine from sslscan output")
        add_default_parser_arguments(parser_task1, False)
        parser_task1.set_defaults(func=self.solve)
    

    def tls_single(self, host, allow_white_ciphers, timeout, errors, verbose):
        try:
            expired_cert_re = r"Not valid after:\s+\x1b\[31m(.*)\x1b\[0m"
            
            weak_versions = []
            weak_ciphers = set()
            weak_bits = []
            is_wrong_host = False
            is_cert_expired = ""
            
            command = ["sslscan", "--no-fallback", "--no-renegotiation", "--no-group", "--no-heartbleed", "--iana-names", f"--connect-timeout={timeout}", str(host)]
            result = subprocess.run(command, text=True, capture_output=True)
            
            # Fail conditions
            if "Connection refused" in result.stderr or "enabled" not in result.stdout:
                return 

            expired_match = re.search(expired_cert_re, result.stdout)
            if expired_match:
                is_cert_expired = expired_match.group(1)

            lines = result.stdout.splitlines()
            protocol_line = False
            cipher_line = False
            for line in lines:
                if "SSL/TLS Protocols" in line:
                    protocol_line = True
                    continue
                if "Supported Server Cipher(s)" in line:
                    protocol_line = False
                    cipher_line = True
                    continue
                if "Server Key Exchange Group(s)" in line:
                    cipher_line = False
                    continue
                if protocol_line:
                    if "enabled" in line:
                        if "SSLv2" in line:
                            weak_versions.append("SSLv2")
                        elif "SSLv3" in line:
                            weak_versions.append("SSLv3")
                        elif "TLSv1.0" in line:
                            weak_versions.append("TLSv1.0")
                        elif "TLSv1.1" in line:
                            weak_versions.append("TLSv1.1")
                
                if cipher_line and line:
                    cipher = line.split()[4]
                    if "[32m" not in cipher: # Non-green
                        if allow_white_ciphers: # We allow white ciphers
                            if "[" in cipher: # Non-white
                                weak_ciphers.add(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                                bit = line.split()[2]
                                if "[33m]" in bit: # If it is a green or white output and bit is low
                                    weak_bits.append(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                        else:
                            weak_ciphers.add(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                            bit = line.split()[2] # If it is a green output and bit is low
                            if "[33m]" in bit:
                                weak_bits.append(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
        except Exception as e:
            self._print_exception(f"Error for {host}: {e}")
                    
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host.ip, int(host.port)), timeout=timeout) as sock:
                context.wrap_socket(sock, server_hostname=host.ip)
        except ssl.CertificateError as e:
            if e.strerror and "Hostname mismatch" in e.strerror:
                is_wrong_host = True
        except Exception as e: 
            self._print_exception(f"Error for {host}: {e}")
        
        return TLS_Vuln_Data(host, weak_versions, list(weak_ciphers), weak_bits, is_wrong_host, is_cert_expired)

    def tls_nv(self, hosts, allow_white_ciphers, threads, timeout, errors, verbose):
        weak_versions = {}
        weak_ciphers = {}
        weak_bits = {}
        wrong_hosts = []
        expired_cert_hosts = []
        results: list[TLS_Vuln_Data] = get_default_context_execution("TLS Misconfigurations", threads, hosts, (self.tls_single, allow_white_ciphers, timeout, errors, verbose))

        for r in results:
            for z in r.weak_versions:
                if z not in weak_versions:
                    weak_versions[z] = []
                weak_versions[z].append(r.host)
            for z in r.weak_ciphers:
                if z not in weak_ciphers:
                    weak_ciphers[z] = []
                weak_ciphers[z].append(r.host)
            for z in r.weak_bits:
                if z not in weak_bits:
                    weak_bits[z] = []
                weak_bits[z].append(r.host)

            if r.is_wrong_hostname:
                wrong_hosts.append(r.host)
            if r.is_cert_expired:
                expired_cert_hosts.append(f"{r.host} - {r.is_cert_expired}")
        
        if len(weak_ciphers) > 0:       
            print("Vulnerable TLS Ciphers on Hosts:")                
            for key, value in weak_ciphers.items():
                print(f"    {key} - {", ".join(value)}")
        
        
        if len(weak_versions) > 0: 
            print()             
            print("Vulnerable TLS Versions on Hosts:")                
            for key, value in weak_versions.items():
                print(f"    {key} - {", ".join(value)}")
                
        if len(weak_bits) > 0:
            print()
            print("Low Bits on Good Algorithms on Hosts:")
            for key, value in weak_versions.items():
                print(f"    {key} - {", ".join(value)}")
        
        if len(wrong_hosts) > 0:
            print()
            print("Wrong hostnames on certficate on hosts:")
            for v in wrong_hosts:
                print(f"    {v}")
                
        if len(expired_cert_hosts) > 0:
            print()
            print("Expired cert on hosts:")
            for v in expired_cert_hosts:
                print(f"    {v}")
    