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
        return None

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
    parser.add_argument("-f", "--file", type=str, required=True, help="Input file name, format is 'host:port => username:password'")
    parser.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    
    args = parser.parse_args()
    
    for entry in get_hosts_from_file(args.file):
        host, cred = entry.split(" => ")
        ip, port = host.split(":")
        username, password = cred.split(":")
        client = ssh_connect(ip, port, username, password)
        if not client: continue
        sftp = client.open_sftp()
        l = sftp.listdir_attr()
        for a in l:
            print(a.st_mode & 0o40000)
            print(a)
