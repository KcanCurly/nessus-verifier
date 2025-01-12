from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
import argparse
import os
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor

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

def bruteforce(host):
    ip = host
    port = 21
    if ":" in host:
        ip = host.split(":")[0]
        port  = int(host.split(":")[1])
    host = ip + ":" + str(port)
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
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    for host in hosts:
        ip = host
        port = "21"
        if ":" in host:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
            
        command = ["sslscan", "--starttls-ftp", "-no-fallback", "--no-renegotiation", "--no-group", "--no-check-certificate", "--no-heartbleed", "--iana-names", host]
        result = subprocess.run(command, text=True, capture_output=True)
        if "Connection refused" in result.stderr or "enabled" not in result.stdout:
            continue
        
        host = ip + ":" + port
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
            if "erver Key Exchange Group(s)" in line:
                cipher_line = False
                continue
            if protocol_line:
                if "enabled" in line:
                    if "SSLv2" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("SSLv2")
                    elif "SSLv3" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("SSLv3")
                    elif "TLSv1.0" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("TLSv1.0")
                    elif "TLSv1.1" in line:
                        if host not in weak_versions:
                            weak_versions[host] = []
                        weak_versions[host].append("TLSv1.1")
            
            if cipher_line and line:
                cipher = line.split()[4]
                if "[32m" not in cipher: # If it is not green output
                    if host not in weak_ciphers:
                        weak_ciphers[host] = []
                    weak_ciphers[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                    continue
                bit = line.split()[2] # If it is a green output and bit is low
                if "[33m]" in bit:
                    if host not in weak_bits:
                        weak_bits[host] = []
                    weak_bits[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', bit) + "->" + re.sub(r'^\x1b\[[0-9;]*m', '', cipher))
                    
      
    if len(weak_ciphers) > 0:       
        print("Vulnerable TLS Ciphers on Hosts:")                
        for key, value in weak_ciphers.items():
            print(f"\t{key} - {", ".join(value)}")
    
    
    if len(weak_versions) > 0: 
        print()             
        print("Vulnerable TLS Versions on Hosts:")                
        for key, value in weak_versions.items():
            print(f"\t{key} - {", ".join(value)}")
            
    if len(weak_bits) > 0:
        print()
        print("Low Bits on Good Algorithms on Hosts:")
        for key, value in weak_versions.items():
            print(f"\t{key} - {", ".join(value)}")

def brute(hosts):
    threads = 10
    
    print("Trying default credentials, this can take time.")
    with ThreadPoolExecutor(threads) as executor:
        executor.map(lambda host: bruteforce(host), hosts)
        
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
        

def check(directory_path, hosts = "hosts.txt"):
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
        
        
    # Anon
    print()
    anon(hosts)

    # Check TLS
    print()
    tls(hosts)
            
    # bruteforce
    print()
    brute(hosts)
            

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")