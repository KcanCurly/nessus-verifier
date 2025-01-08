import argparse
import os

def check(directory_path, hosts = "hosts.txt"):
    if os.path.exists(os.path.join(directory_path, hosts)):
        print("Telnet:")
        with open(os.path.join(directory_path, hosts), "r") as file:
            for line in file:
                print(f"\t{line}")
    

def main():
    parser = argparse.ArgumentParser(description="Telnet module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")