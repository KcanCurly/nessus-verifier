from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
from concurrent.futures import ThreadPoolExecutor
from src.utilities.utilities import confirm_prompt, control_TLS, get_hosts_from_file

creds = [
"anonymous:anonymous",
"root:rootpasswd",
"root:12hrs37",
"ftp:b1uRR3",
"admin:admin",
"localadmin:localadmin",
"admin:1234",
"apc:apc",
"admin:nas",
"Root:wago",
"Admin:wago",
"User:user",
"Guest:guest",
"ftp:ftp",
"admin:password",
"a:avery",
"admin:123456",
"adtec:none",
"admin:admin12345",
"none:dpstelecom",
"instrument:instrument",
"user:password",
"root:password",
"default:default",
"admin:default",
"nmt:1234",
"admin:Janitza",
"supervisor:supervisor",
"user1:pass1",
"avery:avery",
"IEIeMerge:eMerge",
"ADMIN:12345",
"beijer:beijer",
"Admin:admin",
"admin:1234",
"admin:1111",
"root:admin",
"se:1234",
"admin:stingray",
"device:apc",
"apc:apc",
"dm:ftp",
"dmftp:ftp",
"httpadmin:fhttpadmin",
"user:system",
"MELSEC:MELSEC",
"QNUDECPU:QNUDECPU",
"ftp_boot:ftp_boot",
"uploader:ZYPCOM",
"ftpuser:password",
"USER:USER",
"qbf77101:hexakisoctahedron",
"ntpupdate:ntpupdate",
"sysdiag:factorycast@schneider",
"wsupgrade:wsupgrade",
"pcfactory:pcfactory",
"loader:fwdownload",
"test:testingpw",
"webserver:webpages",
"fdrusers:sresurdf",
"nic2212:poiuypoiuy",
"user:user00",
"su:ko2003wa",
"MayGion:maygion.com",
"admin:9999",
"PlcmSpIp:PlcmSpIp",
]

def brute_nv(host, creds: list[str], errors, verbose):
    try:
        ip = host.split(":")[0]
        port  = int(host.split(":")[1])
        
        for cred in creds:
            username, password = cred.split(":")
            try:
                ftp = FTP()
                ftp.connect(ip, port, timeout=10)
                l = ftp.login(username, password)
                if "230" in l:
                    print(f"[+] {host} => {username}:{password}")
            except Error as e:
                if "must use encryption" in str(e):
                    ftp = FTP_TLS()
                    ftp.connect(ip, port, timeout=10)
                    try:
                        l = ftp.login(username, password)
                        if "230" in l:
                            print(f"[+] {host} => {username}:{password}")
                    except error_perm as ee:
                        if errors: print("Error:", ee)
                        continue
                    except Error as eee:
                        if errors: print("Error:", eee)
                        continue
    except Exception as e: 
        if errors: print("Error:", e)
        
def anon_nv(hosts, errors = False, verbose = False):
    anon = []

    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = int(host.split(":")[1])

            ftp = FTP()
            ftp.connect(ip, port, timeout=10)
            try:
                l = ftp.login()
                if "230" in l:
                    anon.append(host)

            except Error as e:
                ftp = FTP_TLS()
                ftp.connect(ip, port, timeout=10)
                try:
                    l = ftp.login()
                    if "230" in l:
                        anon.append(host)
                except error_perm as ee:
                    if errors: print("Error:", ee)
                    continue
                except Error as eee:
                    if errors: print("Error:", eee)
                    continue

        except Exception as e:
            if errors: print("Error:", e)
                    
                    
    if len(anon) > 0:
        print("Anonymous Access on Hosts:")               
        for a in anon:
            print(f"    {a}")

def tls(hosts):
    control_TLS(hosts, "--starttls-ftp")

def brute_nv(hosts: list[str], creds: list[str], threads, errors, verbose):
    with ThreadPoolExecutor(threads) as executor:
        for host in hosts:
            executor.submit(brute_nv, host, creds, errors, verbose)
        
def ssl(hosts):
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
    anon_nv(get_hosts_from_file(args.file), args.errors, args.verbose)
    
def brute_console(args):
    brute_nv(get_hosts_from_file(args.file), get_hosts_from_file(args.credential_file), args.threads, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("ftp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_anon = subparsers.add_parser("anonymous", help="Checks if anonymous login is possible")
    parser_anon.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_anon.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_anon.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_anon.set_defaults(func=anon_console)
    
    parser_brute = subparsers.add_parser("brute", help="Bruteforce ftp login")
    parser_brute.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_brute.add_argument("-cf", "--credential-file", type=str, required=True, help="credential file seperated by new line, user:pass on each line")
    parser_brute.add_argument("-t", "--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    parser_brute.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_brute.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_brute.set_defaults(func=brute_console)
    