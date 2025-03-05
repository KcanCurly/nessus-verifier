import argparse
import pprint
import subprocess
import re
from src.utilities.utilities import get_hosts_from_file
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.services.service import Vuln_Data
from rich.console import Group
from rich.panel import Panel
from pymongo import MongoClient
import pymongo

def post_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            client = MongoClient(ip, int(port))
            dbs = client.list_databases()
            for db in dbs:
                print(f"Database: {db["name"]}")
                print("=====================")
                d = client[db["name"]]
                cols = d.list_collections()
                for c in cols:
                    print(c["name"])
                    print("---------------------")
                    doc = d[c["name"]]
                    for post in doc.find(filter="", limit=5):
                        pprint.pprint(post)
                    print()
                        
                print()

        except:pass
        
def post_console(args):
    post_nv(get_hosts_from_file(args.file))


def unauth_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    vuln = []
    
    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            with pymongo.timeout(timeout):
                client = MongoClient(ip, int(port))
                dbs = client.list_databases()
                vuln.append(host)

        except:pass
    
    if len(vuln) > 0:
        print("MongoDB Unauthenticated Access:")
        for v in vuln:
            print(f"    {v}")

def unauth_console(args):
    unauth_nv(get_hosts_from_file(args.file))

def version_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    versions = {}
    
    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            with pymongo.timeout(timeout):
                client = MongoClient(ip, int(port))
                version = client.server_info()['version']
                if version not in versions:
                    versions[version] = set()
                versions[version].add(host)  
        except:pass
                    
    versions = dict(sorted(versions.items(), reverse=True))
    if len(versions) > 0:       
        print("MongoDB versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")

def version_console(args):
    version_nv(get_hosts_from_file(args.file))

def main():
    parser = argparse.ArgumentParser(description="MongoDB module of nessus-verifier.")
    
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    
    parser_all = subparsers.add_parser("all", help="Runs all modules (Except post module")
    parser_all.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_all.add_argument("-u", "--username", type=str, default="postgres", help="Username (Default = postgres)")
    parser_all.add_argument("-p", "--password", type=str, default="", help="Username (Default = '')")
    parser_all.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_all.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_all.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_all.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_all.set_defaults(func=all)
    
    parser_version = subparsers.add_parser("version", help="Checks version")
    parser_version.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_version.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_version.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_version.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_version.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_version.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_version.set_defaults(func=version_console)
    

    parser_unauth = subparsers.add_parser("unauth", help="Checks if unauthenticated access is allowed")
    parser_unauth.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_unauth.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_unauth.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_unauth.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_unauth.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_unauth.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_unauth.set_defaults(func=unauth_console)
    """
    parser_brute = subparsers.add_parser("brute", help="Bruteforce")
    parser_brute.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_brute.add_argument("-cf", "--credential-file", type=str, help="Credential file")
    parser_brute.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_brute.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_brute.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_brute.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_brute.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_brute.set_defaults(func=brute_console)
    """
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_post.add_argument("-u", "--username", type=str, required=True, help="Username")
    parser_post.add_argument("-p", "--password", type=str, required=True, help="Password")
    parser_post.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_post.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_post.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_post.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_post.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_post.set_defaults(func=post_console)
    
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()