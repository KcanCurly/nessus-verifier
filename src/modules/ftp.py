from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
import argparse
import os
import subprocess
import re

anon = []
weak_versions = {}
weak_ciphers = {}
creds = [
"anonymous:anonymous"
"root:rootpasswd"
"root:12hrs37"
"ftp:b1uRR3"
"admin:admin"
"localadmin:localadmin"
"admin:1234"
"apc:apc"
"admin:nas"
"Root:wago"
"Admin:wago"
"User:user"
"Guest:guest"
"ftp:ftp"
"admin:password"
"a:avery"
"admin:123456"
"adtec:none"
"admin:admin12345"
"none:dpstelecom"
"instrument:instrument"
"user:password"
"root:password"
"default:default"
"admin:default"
"nmt:1234"
"admin:Janitza"
"supervisor:supervisor"
"user1:pass1"
"avery:avery"
"IEIeMerge:eMerge"
"ADMIN:12345"
"beijer:beijer"
"Admin:admin"
"admin:1234"
"admin:1111"
"root:admin"
"se:1234"
"admin:stingray"
"device:apc"
"apc:apc"
"dm:ftp"
"dmftp:ftp"
"httpadmin:fhttpadmin"
"user:system"
"MELSEC:MELSEC"
"QNUDECPU:QNUDECPU"
"ftp_boot:ftp_boot"
"uploader:ZYPCOM"
"ftpuser:password"
"USER:USER"
"qbf77101:hexakisoctahedron"
"ntpupdate:ntpupdate"
"sysdiag:factorycast@schneider"
"wsupgrade:wsupgrade"
"pcfactory:pcfactory"
"loader:fwdownload"
"test:testingpw"
"webserver:webpages"
"fdrusers:sresurdf"
"nic2212:poiuypoiuy"
"user:user00"
"su:ko2003wa"
"MayGion:maygion.com"
"admin:9999"
"PlcmSpIp:PlcmSpIp"
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
                    l = ftp.login()
                    if "230" in l:
                        print(f"[+] {host} => {username}:{password}")
                except error_perm as ee:
                    continue
                except Error as eee:
                    continue
    
        
    

def check(directory_path, hosts = "hosts.txt"):
    with open(os.path.join(directory_path, hosts), "r") as file:
        
        hosts = [line.strip() for line in file if line.strip()] 
        
        
    # Anon    
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

    # Check TLS      
    for host in hosts:
        ip = host
        port = "21"
        if ":" in host:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
            
        command = ["sslscan", "--starttls-ftp", "-no-fallback", "--no-renegotiation", "--no-group", "--no-check-certificate", "--no-heartbleed", "--iana-names", ip + ":" + port]
        result = subprocess.run(command, text=True, capture_output=True)
        if "Connection refused" in result.stderr or "enabled" not in result.stdout:
            continue
        
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
                        if ip + ":" + port not in weak_versions:
                            weak_versions[ip + ":" + port] = []
                        weak_versions[ip + ":" + port].append("SSLv2")
                    elif "SSLv3" in line:
                        if ip + ":" + port not in weak_versions:
                            weak_versions[ip + ":" + port] = []
                        weak_versions[ip + ":" + port].append("SSLv3")
                    elif "TLSv1.0" in line:
                        if ip + ":" + port not in weak_versions:
                            weak_versions[ip + ":" + port] = []
                        weak_versions[ip + ":" + port].append("TLSv1.0")
                    elif "TLSv1.1" in line:
                        if ip + ":" + port not in weak_versions:
                            weak_versions[ip + ":" + port] = []
                        weak_versions[ip + ":" + port].append("TLSv1.1")
            
            if cipher_line and line:
                cipher = line.split()[4]
                if "[32m" not in cipher:
                    if host not in weak_ciphers:
                        weak_ciphers[host] = []
                    weak_ciphers[host].append(re.sub(r'^\x1b\[[0-9;]*m', '', cipher))

      
    if len(weak_ciphers) > 0:       
        print()       
        print("Vulnerable TLS Ciphers on Hosts:")                
        for key, value in weak_ciphers.items():
            print(f"\t{key} - {", ".join(value)}")
    
    
    if len(weak_versions) > 0: 
        print()             
        print("Vulnerable TLS Versions on Hosts:")                
        for key, value in weak_versions.items():
            print(f"\t{key} - {", ".join(value)}")
            
    # bruteforce
    for host in hosts:
        ip = host
        port = "21"
        if ":" in host:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
    
            

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")