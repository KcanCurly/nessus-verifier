import configparser
import argparse
import socket
import struct
import time
from pathlib import Path
import os
from utilities import get_hosts_from_file


def check(directory_path, config, verbose, hosts = "hosts.txt"):
    vuln = {}
    hosts = get_hosts_from_file(hosts)
    
    for host in hosts:
        ip = host.split(":")[0]
        port = host.split(":")[0]
        try:
        # Create a socket for the Time Protocol (TCP)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)  # Set a timeout for the connection
                s.connect((ip, port))  # Connect to the server
                
                # Receive the 4-byte binary time response
                data = s.recv(4)
                if len(data) != 4:
                    # print("Invalid response length.")
                    return
                
                # Unpack the 4-byte response as an unsigned integer
                server_time = struct.unpack("!I", data)[0]
                
                # Convert the server time to seconds since the Unix epoch
                unix_time = server_time - 2208988800  # Subtract Time Protocol epoch (1900) offset
                
                # Display the time in human-readable format
                vuln[host] = f"Server time: {time.ctime(unix_time)}"
        except socket.timeout:
            # print("Connection timed out.")
            pass
        except Exception as e:
            # print(f"An error occurred: {e}")
            pass
    
    if len(vuln):
        print("")

def main():
    parser = argparse.ArgumentParser(description="Time Protocol module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    parser.add_argument("-c", "--config", type=str, required=False, help="Config file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    
    
    args = parser.parse_args()
    
    if not args.config:
        args.config = os.path.join(Path(__file__).resolve().parent.parent, "nvconfig.config")
        
    config = configparser.ConfigParser()
    config.read(args.config)
        
    
    check(args.directory or os.curdir, config, args.verbose, args.filename or "hosts.txt")