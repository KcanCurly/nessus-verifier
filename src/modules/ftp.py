from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
import argparse
import os
import subprocess

anon = []
sslv2 = []
sslv3 = []
tls10 = []
tls11 = []
weak_versions = {}
weak_ciphers = {}

def check(directory_path, hosts = "hosts.txt"):
    with open(os.path.join(directory_path, hosts), "r") as file:
        
        hosts = [line.strip() for line in file if line.strip()] 
        
    for host in hosts:
        ip = host
        port = 21
        if ":" in host:
            ip = host.split(":")[0]
            port  = int(host.split(":")[1])
        ftp = FTP()
        ftp.connect(ip, port)
        try:
            l = ftp.login()
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
        with open(os.path.join(directory_path, "result.txt"), "a") as z:
            z.write("Anonymous access:")               
            for a in anon:
                z.write(f"\t{a}")
                
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
                    if cipher.startswith("["):
                        weak_ciphers[host].append(cipher[4:])
                    else: weak_ciphers[host].append(cipher)
      
    if len(weak_ciphers) > 0:              
        print("Vulnerable TLS Cipher on Hosts:")                
        for key, value in weak_ciphers.items():
            print(f"\n{key} - {", ".join(value)}")
    
    if len(weak_versions) > 0:              
        print("Vulnerable TLS Version on Hosts:")                
        for key, value in weak_versions.items():
            print(f"\n{key} - {", ".join(value)}")
            
                
        

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")