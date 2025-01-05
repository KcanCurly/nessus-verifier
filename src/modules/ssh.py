import subprocess
import argparse
import os

def check(directory_path, hosts = "hosts.txt"):
    
    ### ssh-audit to capture version

    command = ["ssh", "-vvv", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
    
    with open(os.path.join(directory_path, hosts), "r") as file:
        hosts = [line.strip() for line in file if line.strip()]  # Remove empty lines and whitespace
        
    
    # Iterate over each host and run the command
    for host in hosts:
        # print(f"Running command for host: {host}")
        
        command = ["ssh", "-vvv", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", host]
        
        try:
            # Execute the command and capture the output
            result = subprocess.run(command, text=True, capture_output=True)
            first_line = result.stdout.splitlines()[0]
            first_word = first_line.split()[0]
        
            # Print the output of the command
            print(f"{host}: {first_word}")

        except Exception as e:
            # Handle errors (e.g., if the host is unreachable)
            print(f"{e}")
            try:
                
                first_line = result.stdout.splitlines()[0]
                first_word = first_line.split()[0]
            
                # Print the output of the command
                print(f"{host}: {first_word}")
            except Exception as e:
                continue
    

def main():
    parser = argparse.ArgumentParser(description="SSH module of nessus-verifier.")
    parser.add_argument("-d", "--directory", type=str, required=False, help="Directory to process (Default = current directory).")
    parser.add_argument("-f", "--filename", type=str, required=False, help="File that has host:port information.")
    
    args = parser.parse_args()
    
    check(args.directory or os.curdir, args.filename or "hosts.txt")