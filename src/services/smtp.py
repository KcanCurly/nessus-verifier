import argparse
import smtplib
import configparser
import os
from pathlib import Path
import re
import subprocess
from src.utilities.utilities import confirm_prompt, control_TLS


def userenum(directory_path, config, hosts = "hosts.txt"):
    vuln = {}
    def check_enum(smtpp):
        try:
            answer = smtpp.docmd("VRFY", "test")
            if answer[0] == 250 or "unknown" in answer[1].decode().lower():
                if host not in vuln:
                    vuln[host] = []
                vuln[host].append("VRFY")
        except: pass
        
        try:
            answer = smtpp.docmd("EXPN", "test")
            if answer[0] == 250 or "unknown" in answer[1].decode().lower():
                if host not in vuln:
                    vuln[host] = []
                vuln[host].append("EXPN")
        except: pass
        
        try:
            answer = smtpp.docmd("MAIL FROM:", "test@test.com")
            if "STARTTLS" in answer[1].decode():
                smtp = smtplib.SMTP(ip, port, timeout=5)
                smtp.starttls()
                check_enum(smtp)
                return

            answer = smtpp.docmd("RCPT TO:", f"<a@{config["smtp"]["Domain"]}>")
            if answer[0] == 250 or "unknown" in answer[1].decode().lower():
                if host not in vuln:
                    vuln[host] = []
                vuln[host].append("RCPT")
        except: pass
            

    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
    for host in hosts:
        ip = host.split(":")[0]
        port  = host.split(":")[1]
        try:
            smtp = smtplib.SMTP(ip, port, timeout=5)
            smtp.helo()
            check_enum(smtp)
        except smtplib.SMTPServerDisconnected as t: # It could be that server requires TLS/SSL so we need to connect again with TLS
            try:
                smtp = smtplib.SMTP_SSL(ip, port, timeout=5)
                smtp.helo()
                check_enum(smtp)
            except: pass
        except: pass
                
    
    if len(vuln) > 0:
        print("User Enumeration Was Possible with Given Methods on Hosts:")
        for key, value in vuln.items():
            print(f"\t{key} - {", ".join(value)}")
            

def tls(directory_path, config, hosts):
    control_TLS(hosts, "--starttls-smtp")
    
def tls_check(directory_path, config, hosts):
    if not os.path.exists(os.path.join(directory_path, hosts)):
        return
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()] 
    tls = []
    for host in hosts:
        try:
            sm = smtplib.SMTP(timeout=5)
            sm.connect(host)
            sm.helo() # Some smtp services requires helo first and also we need to get domain name
            dom = config["smtp"]["Domain"]
            answer = sm.docmd("MAIL FROM:", f"nessus-verifier-test@{dom}")[1].decode()
            if "STARTTLS" not in answer:
                tls.append(host)
                
        except TimeoutError as t: # If we get time out its either host is not up or it requires TLS/SSL, in either case we don't need to check it
           pass
        except Exception as e:
            print("Error: ", e)
                
    if len(tls) > 0:
        print("SMTP servers that does NOT force TLS/SSL:")
        for t in tls:
            print(f"\t{t}")
            
def open_relay(hosts, confirm, subject, message, client1, client2, in_fake, out_fake, out_real, temp, timeout = 3):
    vuln = {}
        
    def sendmail(sender, receiver, tag):
        m = f'Subject: {subject}\n\n{message}'
        try:
            smtp = smtplib.SMTP(ip, port, timeout=timeout)
            smtp.sendmail(sender,receiver,m)
            if f"{ip}:{port}" not in vuln:
                vuln[f"{ip}:{port}"] = []
            vuln[f"{ip}:{port}"].append(tag)
        except smtplib.SMTPServerDisconnected as t: # It could be that server requires TLS/SSL so we need to connect again with TLS
            try:
                smtp = smtplib.SMTP_SSL(ip, port, timeout=timeout)
                smtp.sendmail(sender,receiver,m)
                if f"{ip}:{port}" not in vuln:
                    vuln[f"{ip}:{port}"] = []
                vuln[f"{ip}:{port}"].append(tag)
            except Exception as er:
                print("Er: ", er)
                pass
                
        except smtplib.SMTPSenderRefused as ref: # It could be that server requires starttls
            if "STARTTLS" in ref.smtp_error.decode():
                try:
                    smtp = smtplib.SMTP(ip, port, timeout=timeout)
                    smtp.starttls()
                    smtp.sendmail(sender,receiver,m)
                    if f"{ip}:{port}" not in vuln:
                        vuln[f"{ip}:{port}"] = []
                    vuln[f"{ip}:{port}"].append(tag)
                except: pass
            else: pass
        except: pass
    
    
    if not confirm:
        print(f"Client1 is {client1}")
        print(f"Client2 is {client2}")
        print(f"In fake is {in_fake}")
        print(f"Fake out is {out_fake}")
        print(f"Real out is {out_real}")
        print(f"Temp is {temp}")
        print("Note: You can bypass this prompt by adding --confirm")
        if not confirm_prompt("Do you want to continue with those emails?"):
            return
        
    
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[1]
            
        
        sendmail(client1, client1, "Client 1 -> Client 1")
        sendmail(client2, client1, "Client 2 -> Client 1")
        sendmail(in_fake, client1, "Fake In -> Client 1")
        sendmail(out_real, client1, "Out Real -> Client 1")
        sendmail(client1, out_real, "Client 1 -> Out Real")
        sendmail(in_fake, out_real, "In Fake -> Out Real")
        sendmail(out_fake, client1, "Out Fake -> Client 1")
        sendmail(out_fake, temp, "Out Fake -> Temporary Mail")
    
    if len(vuln) > 0:
        print()
        print("Open Relay Test:")
        for key, value in vuln.items():
            print(f"\t{key}: {", ".join(value)}")
    
            
def check(directory_path, config, confirm, verbose, hosts):
    if verbose: print("Starting TLS Check")
    tls_check(directory_path, config, hosts)
    if verbose: print("\nStarting TLS Version/Cipher/Bit Check")
    tls(directory_path, config, hosts)
    if verbose: print("\nStarting Open Relay Test")
    open_relay(directory_path, config, confirm, hosts)
    if verbose: print("\nStarting User Enumeration Test")
    userenum(directory_path, config, hosts)

def main():
    parser = argparse.ArgumentParser(description="SMTP module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("--confirm", action="store_true", help="Verbose")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args.confirm, args.verbose, args.filename or "hosts.txt")