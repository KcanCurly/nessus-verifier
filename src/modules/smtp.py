import argparse
import smtplib
import configparser
import os
from pathlib import Path

def tls(directory_path, config, hosts = "hosts.txt"):
    if not os.path.exists(os.path.join(directory_path, hosts)):
        return
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
    tls = []
    for host in hosts:
        try:
            sm = smtplib.SMTP()
            sm.connect(host)
            sm.helo() # Some smtp services requires helo first and also we need to get domain name
            helo = sm.helo_resp.decode()
            dom = helo.split()[0]
            dom = dom.split(".", 1)[1] # Get domain name
            answer = sm.docmd("MAIL FROM:", f"test@{dom}")[1].decode()
            if "STARTTLS is required to send mail" not in answer:
                tls.append(host)
                
        except Exception as e:
            print("Error: ", e)
                
    if len(tls) > 0:
        print("SMTP that does NOT force TLS/SSL")
        for t in tls:
            print(f"\t{t}")
            
def open_relay(directory_path, config, hosts = "hosts.txt"):
    vuln = {}
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
        
    def sendmail(sender, receiver, tag):
        subject = eval(config["smtp"]["Subject"])
        message = eval(config["smtp"]["Message"])
        message = f'Subject: {subject}\n\n{message}'
        try:
            smtp = smtplib.SMTP(ip, port, timeout=5)
            smtp.sendmail(sender,receiver,message)
            if f"{ip}:{port}" not in vuln:
                vuln[f"{ip}:{port}"] = []
            vuln[f"{ip}:{port}"].append(tag)
        except Exception as error:
            pass
    
    
    client1 = config["smtp"]["Client1"]
    client2 = config["smtp"]["Client2"]
    fake_in = config["smtp"]["Fake_in"]
    real_out = config["smtp"]["Real_out"]
    fake_out = config["smtp"]["Fake_out"]
    temp = config["smtp"]["Temp"]
    
    
    for host in hosts:
        ip = host
        port = 25
        if ":" in host:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
        
        sendmail(client1, client1, "Client 1 -> Client 1")
        sendmail(client2, client1, "Client 2 -> Client 1")
        sendmail(fake_in, client1, "Fake In -> Client 1")
        sendmail(real_out, client1, "Real Out -> Client 1")
        sendmail(client1, real_out, "Client 1 -> Real Out")
        sendmail(fake_in, real_out, "Fake In -> Real Out")
        sendmail(fake_out, client1, "Fake Out -> Client 1")
        sendmail(fake_out, temp, "Fake Out -> Temporary Mail")
    
    if len(vuln) > 0:
        for key, value in vuln.items():
            print(f"{key}: {", ".join(value)}")
    
            
def check(directory_path, config, hosts = "hosts.txt"):
    tls(directory_path, config, hosts)
    open_relay(directory_path, config, hosts)

def main():
    parser = argparse.ArgumentParser(description="SMTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args.filename or "hosts.txt")