from ftplib import FTP
from ftplib import Error
from ftplib import FTP_TLS
import argparse
import os

def check(directory_path, hosts = "hosts.txt"):
    hosts_path = os.path.join(directory_path, hosts)
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
        
    for host in hosts:
        ftp = FTP(host)
        try:
            l = ftp.login()
            print("l: ", l)
        except Error as e:
            if "must use encryption" in str(e):
                ftp = FTP_TLS(host)
                try:
                    l = ftp.login()
                    print("l: ", l)
                except Error as ee:
                    print("ee: ", str(type(ee)))

def main():
    parser = argparse.ArgumentParser(description="FTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")