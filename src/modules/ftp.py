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
                    print("ee: ", ee)
                except Error as eee:
                    print("something went wrong")
                    
                    
    if anon.count() > 0:
        with open(os.path.join(directory_path, "result.txt"), "a") as z:
            z.write("Anonymous access:")               
            for a in anon:
                z.write(f"\t{a}")
                
    for host in hosts:
        ip = host
        port = 21
        if ":" in host:
            ip = host.split(":")[0]
            port  = int(host.split(":")[1])
            
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
            if protocol_line:
                if "enabled" in line:
                    if "SSLv2" in line:
                        sslv2.append(host)
                    elif "SSLv3" in line:
                        sslv3.append(host)
                    elif "TLSv1.0" in line:
                        tls10.append(host)
                    elif "TLSv1.1" in line:
                        tls11.append(host)
            
            if cipher_line:
                cipher = line.split(" ")[4]
                if "[[32m" not in cipher:
                    if host not in weak_ciphers:
                        weak_ciphers[host] = []
                    if cipher.startswith("^[["):
                        weak_ciphers[host].append(cipher[6:])
                    else: weak_ciphers[host].append(cipher)
                    
    print("Vulnerable hosts:")                
    for key, value in weak_ciphers.items():
        print(f"\n{key} - {", ".join(value)}")
                
            
                
        

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")