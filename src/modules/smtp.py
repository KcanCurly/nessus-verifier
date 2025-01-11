import argparse
import smtplib
import os

def tls(directory_path, hosts = "hosts.txt"):
    if not os.path.exists(os.path.join(directory_path, hosts)):
        return
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
    
    for host in hosts:
        try:
            sm = smtplib.SMTP()
            sm.connect(host)
            sm.helo() # Some smtp services requires helo first
            answer = sm.docmd("MAIL TO", "test")
            print(answer)
            
        except Exception as e:
            print("Error: ", e)
        
         
             
        
             
    

def main():
    parser = argparse.ArgumentParser(description="SMTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")