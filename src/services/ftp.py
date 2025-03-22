from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
from src.utilities.utilities import control_TLS, get_hosts_from_file, get_default_context_execution, add_default_parser_arguments

class FTP_Anon_Vuln_Data():
    def __init__(self, host: str, is_TLS: bool):
        self.host = host
        self.is_TLS = is_TLS
        
class FTP_Brute_Vuln_Data():
    def __init__(self, host: str, is_TLS: bool, creds: list[str]):
        self.host = host
        self.is_TLS = is_TLS
        self.creds = creds

def brute_single(host, creds: list[str], timeout = 3, errors = False, verbose = False):
    vuln = FTP_Brute_Vuln_Data(host, False, [])

    ip, port = host.split(":")
    
    for cred in creds:
        try:
            username, password = cred.split(":")
            ftp = FTP()
            ftp.connect(ip, int(port), timeout=timeout)
            l = ftp.login(username, password)
            if "230" in l:
                vuln.creds.append(f"{username}:{password}")
                ftp.close()
        except Error:
            try:
                ftp = FTP_TLS()
                ftp.connect(ip, int(port), timeout=timeout)
                l = ftp.login(username, password)
                if "230" in l:
                    vuln.is_TLS = True
                    vuln.creds.append(f"{username}:{password}")
                    ftp.close()
                else: ftp.close()
            except error_perm as ee:
                if errors: print("Error:", ee)
                ftp.close()
                continue
            except Error as eee:
                if errors: print("Error:", eee)
                ftp.close()
                continue

    if len(vuln.creds) > 0: return vuln
    return None
   
def anon_single(host, timeout = 10, errors = False, verbose = False):
        try:
            ip, port = host.split(":")

            ftp = FTP()
            ftp.connect(ip, int(port), timeout=timeout)
            try:
                l = ftp.login()
                if "230" in l:
                    return FTP_Anon_Vuln_Data(host, False)

            except Error as e:
                ftp = FTP_TLS()
                ftp.connect(ip, int(port), timeout=timeout)
                try:
                    l = ftp.login()
                    if "230" in l:
                        return FTP_Anon_Vuln_Data(host, True)
                except error_perm as ee:
                    if errors: print("Error:", ee)
                except Error as eee:
                    if errors: print("Error:", eee)

        except Exception as e:
            if errors: print("Error:", e)
            
        return None
        
def anon_nv(hosts, threads = 10, timeout = 5, errors = False, verbose = False):
    results: list[FTP_Anon_Vuln_Data] = get_default_context_execution("FTP Anon", threads, hosts, (anon_single, timeout, errors, verbose))
                    
    if len(results) > 0:
        print("FTP Anonymous Access on Hosts:")               
        for a in results:
            print(f"    {a}{" [TLS]" if a.is_TLS else ""}")

def tls(hosts):
    control_TLS(hosts, "--starttls-ftp")

def brute_nv(hosts: list[str], creds: list[str], threads, timeout, errors, verbose):
    results: list[FTP_Brute_Vuln_Data] = get_default_context_execution("FTP Brute", threads, hosts, (brute_single, creds, timeout, errors, verbose))
    
    if len(results) > 0:
        print("FTP Credentials Found on Hosts:")               
        for a in results:
            print(f"    {a}{" [TLS]" if a.is_TLS else ""} - {", ".join(a.creds)}")

        
def ssl_check(hosts):
    dict = {}
    for host in hosts:
        try:
            ip = host
            port = 21
            if ":" in host:
                ip = host.split(":")[0]
                port  = int(host.split(":")[1])
            host = ip + ":" + str(port)
            ftp = FTP()
            ftp.connect(ip, port)
            try:
                l = ftp.login()
                if "230" in l:
                    if host not in dict:
                        dict[host] = []
                    dict[host].append("Anonymous")
            except Error as e:
                pass
            
            ftp = FTP()
            ftp.connect(ip, port)
            try:
                l = ftp.login()
                if "230" in l:
                    if host not in dict:
                        dict[host] = []
                    dict[host].append("Local")
            except Error as e:
                pass
        except Exception as e: print(e)
        
        
    if len(dict) > 0:
        print("SSL Not Forced:")
        for key, value in dict.items():
            print(f"    {key} - {", ".join(value)}")
        
            
def anon_console(args):
    anon_nv(get_hosts_from_file(args.target), args.errors, args.verbose)
    
def brute_console(args):
    brute_nv(get_hosts_from_file(args.target), get_hosts_from_file(args.credential_file), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ftp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_anon = subparsers.add_parser("anonymous", help="Checks if anonymous login is possible")
    add_default_parser_arguments(parser_anon)
    parser_anon.set_defaults(func=anon_console)
    
    parser_brute = subparsers.add_parser("brute", help="Bruteforce ftp login")
    parser_brute.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_brute.add_argument("credential-file", type=str, help="File name or targets seperated by space, user:pass on each line")
    add_default_parser_arguments(parser_brute, False)
    parser_brute.set_defaults(func=brute_console)
    