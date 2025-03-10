import argparse
import pprint
from src.utilities.utilities import get_hosts_from_file
from pymongo import MongoClient
import pymongo

def post_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    for host in hosts:
        try:
            ip, port = host.split(":")
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


def unauth_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    vuln = []
    
    for host in hosts:
        try:
            ip, port = host.split(":")
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

def version_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    versions = {}
    
    for host in hosts:
        try:
            ip, port = host.split(":")
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

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("mongodb")
    subparsers = parser_task1.add_subparsers(dest="command")
    
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

