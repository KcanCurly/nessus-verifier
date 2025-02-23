import argparse
import pprint
import paramiko
import sys
from src.snaffler.pysnaffler.ruleset import SnafflerRuleSet

from src.utilities.utilities import get_hosts_from_file

def ssh_connect(host, port, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, int(port), username, password)
        return client
    except Exception as e:
        print(f"[!] SSH Connection failed: {e}")
        sys.exit(1)

def list_readable_files(client):
    try:
        command = "find / -type f -readable 2>/dev/null"
        stdin, stdout, stderr = client.exec_command(command)
        files = stdout.read().decode().split('\n')
        return [file for file in files if file.strip()]
    except Exception as e:
        print(f"[!] Error listing files: {e}")
        return []


def main():
    parser = argparse.ArgumentParser(description="Snaffle via SSH.")
    parser.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser.add_argument("-cf", "--credential-file", type=str, required=True, help="Credential file")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    
    args = parser.parse_args()
    
    rule = SnafflerRuleSet.load_default_ruleset()
    pprint.pprint(rule.allRules)
    
    for host in get_hosts_from_file(args.file):
        ip = host.split(":")[0]
        port = host.split(":")[1]
        for cred in get_hosts_from_file(args.credential_file):
            username = cred.split(":")[0]
            password = cred.split(":")[1]
            client = ssh_connect(ip, port, username, password)
            
            files = list_readable_files(client)
            
            for file in files:
                f = file.rsplit("/", 1)
                if rule.enum_file(f[1])[0]:
                    print(f[1])
            
            client.close()
            
            break
    
    