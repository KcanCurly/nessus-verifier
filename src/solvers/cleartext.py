import subprocess
import re
import ssl
import socket
import tomllib
from src.utilities.utilities import find_scan
from src.modules.vuln_parse import GroupNessusScanOutput
from src.utilities import logger
import nmap

code = 7

def helper_parse(subparser):
    parser_task1 = subparser.add_parser(str(code), help="Cleartext Protocol Detected")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="JSON file name")
    parser_task1.set_defaults(func=solve)
    

def solve(args):
    l= logger.setup_logging(args.verbose)
    scan: GroupNessusScanOutput = find_scan(args.file, code)
    if not scan and not args.ignore_fail: 
        print("No id found in json file")
        return
    
    if args.config:
        with open(args.config, "rb") as f:
            data = tomllib.load(f)
    
    hosts = scan.hosts
    
    # AMQP

    try:
        hosts = scan.sub_hosts.get("87733")
        vuln = {}    
        nm = nmap.PortScanner()
        for host in hosts:
            try:
                ip = host.split(":")[0]
                port = host.split(":")[1]
                nm.scan(ip, port, arguments=f'--script amqp-info')
                
                if ip in nm.all_hosts():
                    nmap_host = nm[ip]
                    if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                        tcp_info = nmap_host['tcp'][int(port)]
                        if 'script' in tcp_info and 'amqp-info' in tcp_info['script']:

                            amqpinfo = tcp_info['script']['amqp-info']

                            mech = None

                            for line in amqpinfo.splitlines():
                                if "mechanisms:" in line:
                                    mech = line.split(":")[1].strip()
                            if mech:
                                vuln[host] = mech

            except Exception as e: pass #print(e)
        
        if len(vuln) > 0:
            print("AMQP Plain Authentication Mechanism Detected:")
            for key, value in vuln.items():
                print(f"{key}: {value}")
    except: pass
    
    # Telnet

    try:
        hosts = scan.sub_hosts.get("42263")
        vuln = []   
        nm = nmap.PortScanner()
        for host in hosts:
            try:
                ip = host.split(":")[0]
                port = host.split(":")[1]
                nm.scan(ip, port, arguments=f'-sV')
                
                if ip in nm.all_hosts():
                    nmap_host = nm[ip]
                    for port, details in nm[host]['tcp'].items():
                        service_name = details['name']
                        if service_name.lower() == 'telnet':
                            vuln.append(host)
                        
            except Exception as e: pass #print(e)
        
        if len(vuln) > 0:
            print("Unencrypted Telnet Detected:")
            for value in vuln:
                print(f"{value}")
    except: pass