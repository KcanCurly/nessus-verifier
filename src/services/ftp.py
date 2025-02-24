from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
import argparse
import os
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

def bruteforce(args, host):
    ip = host
    port = 21
    if ":" in host:
        ip = host.split(":")[0]
        port  = int(host.split(":")[1])
    host = ip + ":" + str(port)
    
    if args.creds:
        with open(args.creds, "r") as file:
            c1 = [line.strip() for line in file if line.strip()] 
        
        creds = [*creds, *c1]
    elif args.overwrite_creds:
        with open(args.creds, "r") as file:
            c2 = [line.strip() for line in file if line.strip()] 
        creds = c2
    
    
    for cred in creds:
        username = cred.split(":")[0]
        password = cred.split(":")[1]
        ftp = FTP()
        ftp.connect(ip, port)
        try:
            l = ftp.login(username, password)
            if "230" in l:
                print(f"[+] {host} => {username}:{password}")
        except Error as e:
            if "must use encryption" in str(e):
                ftp = FTP_TLS()
                ftp.connect(ip, port)
                try:
                    l = ftp.login(username, password)
                    if "230" in l:
                        print(f"[+] {host} => {username}:{password}")
                except error_perm as ee:
                    continue
                except Error as eee:
                    continue   
        
def anon(hosts):
    anon = []
    for host in hosts:
        ip = host.split(":")[0]
        port  = int(host.split(":")[1])

        ftp = FTP()
        ftp.connect(ip, port)
        try:
            l = ftp.login()
            if "230" in l:
                anon.append(host)

        except Error as e:
            if "must use encryption" in str(e):
                ftp = FTP_TLS()
                ftp.connect(ip, port)
                try:
                    l = ftp.login()
                    if "230" in l:
                        anon.append(host)
                except error_perm as ee:
                    continue
                except Error as eee:
                    continue
                    
                    
    if len(anon) > 0:
        print("Anonymous Access on Hosts:")               
        for a in anon:
            print(f"\t{a}")

def tls(hosts):
    control_TLS(hosts, "--starttls-ftp")

def brute(args, hosts):
    threads = 10
    
    print("Trying default credentials, this can take time.")
    with ThreadPoolExecutor(threads) as executor:
        executor.map(lambda host: bruteforce(args, host), hosts)
        
def ssl(hosts):
    dict = {}
    for host in hosts:
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
        
    if len(dict) > 0:
        print("SSL Not Forced:")
        for key, value in dict.items():
            print(f"\t{key} - {", ".join(value)}")
        

def check(args, hosts):
    hosts = get_hosts_from_file(hosts)
        
        
    # Anon
    print()
    anon(hosts)

    # Check TLS
    print()
    tls(hosts)
            
    # bruteforce
    print()
    if not confirm_prompt("Do you wish to continue for brute force?"): return   
    brute(args, hosts)
            

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("--creds", type=str, required=False, help="Additional cred file to try.")
    parser.add_argument("--overwrite-creds", type=str, required=False, help="Overwrite default cred file with this file.")
    
    args = parser.parse_args()
    
    check(args, args.filename or "hosts.txt")