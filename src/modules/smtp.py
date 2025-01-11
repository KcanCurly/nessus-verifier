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
            helo = sm.helo_resp.decode()
            dom = helo[1].split()[0]
            dom = dom.split(".", 1)[1]
            print(dom)            
            answer = sm.docmd("MAIL FROM:", f"test@{dom}")
            print(answer)
            
        except Exception as e:
            print("Error: ", e)
        
         
             
def check(directory_path, hosts = "hosts.txt"):
    tls(directory_path, hosts)
    
             
    

def main():
    parser = argparse.ArgumentParser(description="SMTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")