import subprocess
import re
from impacket.smbconnection import SMBConnection
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments, get_default_context_execution
        
class NullGuest_Vuln_Data():
    def __init__(self, host: str, null_files: dict[str, list[str]], guest_files: dict[str, list[str]]):
        self.host = host
        self.null_files = null_files
        self.guest_files = guest_files

def nullguest_single(host, timeout, errors, verbose):
    null_vuln = {}
    guest_vuln = {}
    
    ip, port = host.split(":")

    # Get NetBIOS of the remote computer
    command = ["nmblookup", "-A", ip]
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    netbios_re = r"\s+(.*)\s+<20>"
    
    s = re.search(netbios_re, result.stdout)
    if s:
        nbname = s.group()
        try:
            conn = pysmbconn.SMBConnection('', '', '', nbname, is_direct_tcp=True)
            if conn.connect(ip, 445, timeout=timeout):
                shares = conn.listShares()
                for share in shares:
                    try:
                        files = conn.listPath(share.name, "/")
                        null_vuln[share.name] = []

                        for file in files:
                            if file.filename == "." or file.filename == "..": continue
                            null_vuln[share.name].append(file.filename)
                    except Exception: pass

        except Exception as e:
            if errors: print(f"Error for host {host}: {e}")
        try:
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
        except Exception as e:
            if errors: print(f"Error for host {host}: {e}")
    return NullGuest_Vuln_Data(host, null_vuln, guest_vuln)

def nullguest_nv(hosts, threads, timeout, errors, verbose):
    null_vuln: dict[str, dict[str, list[str]]] = {}
    guest_vuln: dict[str, dict[str, list[str]]] = {}
    results: list[NullGuest_Vuln_Data] = get_default_context_execution("Null/Guest Share Check", threads, hosts, (sign_single, timeout, errors, verbose))
    
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


def nullguest_console(args):
    nullguest_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def sign_single(host, timeout, errors, verbose):
    ip, port = host.split(":")

    try:
        conn = SMBConnection(ip, ip, sess_port=int(port), timeout=timeout)
        if not conn._SMBConnection.is_signing_required(): 
            return host
    except Exception as e:
        if errors: print(f"Error for host {host}: {e}")

def sign_nv(hosts, threads, timeout, errors, verbose):
    results: list[str] = get_default_context_execution("SMB Signing Check", threads, hosts, (sign_single, timeout, errors, verbose))

    if len(results) > 0:
        print("SMB signing NOT enabled on hosts:")
        for v in results:
            print(f"    {v}")

def sign_console(args):
    sign_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def smbv1_single(host, timeout, errors, verbose):
    ip, port = host.split(":")

    try:
        SMBConnection(ip, ip, sess_port=int(port), timeout=timeout, preferredDialect="NT LM 0.12")
        return host
    except Exception as e:
        if errors: print(f"Error for host {host}: {e}")

def smbv1_nv(hosts, threads, timeout, errors, verbose):
    results: list[str] = get_default_context_execution("SMBv1 Check", threads, hosts, (smbv1_single, timeout, errors, verbose))

    if len(results) > 0:
        print("SMBv1 enabled on hosts:")
        for v in results:
            print(f"    {v}")

def smbv1_console(args):
    smbv1_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)


def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("smb")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_smbv1 = subparsers.add_parser("smbv1", help="Checks SMBv1 usage")
    add_default_parser_arguments(parser_smbv1)
    parser_smbv1.set_defaults(func=smbv1_console)
    
    parser_sign = subparsers.add_parser("sign", help="Checks SMB Signing")
    add_default_parser_arguments(parser_sign)
    parser_sign.set_defaults(func=sign_console)
    
    parser_nullguest = subparsers.add_parser("nullguest", help="Checks Null/Guest Share Access")
    add_default_parser_arguments(parser_nullguest)
    parser_nullguest.set_defaults(func=nullguest_console)