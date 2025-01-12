import argparse
import smtplib
import configparser
import os
from pathlib import Path
import re
import subprocess

def tls(directory_path, config, hosts = "hosts.txt"):
    weak_versions = {}
    weak_ciphers = {}
    weak_bits = {}
    for host in hosts:
        ip = host
        port = "21"
        if ":" in host:
            ip = host.split(":")[0]
            port  = host.split(":")[1]
            
        command = ["sslscan", "--starttls-smtp", "-no-fallback", "--no-renegotiation", "--no-group", "--no-check-certificate", "--no-heartbleed", "--iana-names", "--connect-timeout=3", host]
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

def tls_check(directory_path, config, hosts = "hosts.txt"):
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
            try:
                dom = helo.split()[0]
                dom = dom.split(".", 1)[1] # Get domain name
            except:
                dom = config["smtp"]["Domain"]
                if dom is "None":
                    continue # HELO didn't give domain name
            answer = sm.docmd("MAIL FROM:", f"nessus-verifier-test@{dom}")[1].decode()
            if "STARTTLS" not in answer:
                tls.append(host)
                
        except Exception as e:
            print("Error: ", e)
                
    if len(tls) > 0:
        print("SMTP servers that does NOT force TLS/SSL:")
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
    tls_check(directory_path, config, hosts)
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
    c = config.read(args.config)
    if len(c) == 0:
        print("Config file read failed.")
        
    
    check(args.directory or os.curdir, config, args.filename or "hosts.txt")