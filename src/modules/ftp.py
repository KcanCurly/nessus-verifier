from ftplib import FTP
from ftplib import Error
from ftplib import error_perm
from ftplib import FTP_TLS
import argparse
import os
import subprocess

anon = []

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
                    
                    
    if anon.count > 0:
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
        print(result)
        

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")