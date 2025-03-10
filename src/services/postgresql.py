import argparse
import subprocess
import re
from src.utilities.utilities import get_hosts_from_file
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Group
from rich.panel import Panel
import psycopg

creds = [
    "dcmadmin:passw0rd",
    "postgres:amber",
    "postgres:postgres",
    "postgres:password",
    "postgres:admin",
    "admin:admin",
    "admin:password",
    "postgres:123",
]

def brute_nv(l: list[str], c: list[str] = [], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    vuln = {}
    
    creds = creds + c
    
    for host in l:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        for cred in creds:
            u = cred.split(":")[0]
            p = cred.split(":")[1]
            try:
                db_params = {
                    "user": u,
                    "password": p,
                    "host": ip,
                    "port": int(port),
                }
                with psycopg.connect(**db_params) as con:
                    with con.cursor() as cur:
                        cur.execute("SELECT datname FROM pg_database;")
                        if host not in vuln:
                            vuln[host] = []
                        vuln[host].append(cred)

            except: pass
        
    if len(vuln) > 0:
        print("Valid PostgreSQL credential found:")
        for key, value in vuln.items():
            print(f"{key}: {", ".join(value)}")

def brute_console(args):
    brute_nv(get_hosts_from_file(args.file), get_hosts_from_file(args.credential_file) if args.credential_file else [])

def post_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            dbs = []
            db_params = {
                "user": "postgres",
                "password": "",
                "host": ip,
                "port": int(port),
            }
            with psycopg.connect(**db_params) as con:
                with con.cursor() as cur:
                    cur.execute("SELECT datname FROM pg_database;")
                    dbs = [record[0] for record in cur]
            for db in dbs:
                try:
                    db_params = {
                        "dbname": db,
                        "user": "postgres",
                        "password": "",
                        "host": ip,
                        "port": int(port),
                    }
                    with psycopg.connect(**db_params) as con:
                        with con.cursor() as cur:
                            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
                            print(f"DATABASE: {db}")
                            print("=======================")
                            tables = [record[0] for record in cur]
                            for table in tables:
                                try:
                                    print(table)
                                    print("-----------------------")
                                    cur.execute(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{table}';")
                                    columns = []
                                    for c in cur:
                                        print(f"{c[0]}: {c[1]}")
                                        columns.append(c[0])
                                    print()
                                    try:
                                        print("#######################")
                                        cur.execute(f"SELECT {", ".join(columns)} FROM {table} LIMIT 10;")
                                        for v in cur:
                                            print(v)
                                        print()
                                    except Exception as e: print(e)
                                    print()
                                except Exception as e: print(e)
                            
                                
                except Exception as e: print(e)
            
        except Exception as e: print(e)

def post_console(args):
    post_nv(get_hosts_from_file(args.file))

def unpassworded_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    vuln = {}
    
    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            db_params = {
                "user": "postgres",
                "password": "",
                "host": ip,
                "port": int(port),
            }
            with psycopg.connect(**db_params) as con:
                with con.cursor() as cur:
                    cur.execute("SELECT datname FROM pg_database;")
                    dbs = [record[0] for record in cur]
                    vuln[host] = dbs
        except: pass
        
    if len(vuln) > 0:
        print("PostgreSQL servers that allows user postgres with empty password authentication:")
        for key, value in vuln.items():
            print(f"{key}: {", ".join(value)}")
                    
def unpassworded_console(args):
    unpassworded_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose, disable_visual_on_complete=args.disable_visual_on_complete)

def all(args):
    unpassworded_console(args)
    brute_console(args)

def main():
    parser = argparse.ArgumentParser(description="PostgreSQL module of nessus-verifier.")
    
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
    
    parser_default = subparsers.add_parser("default-password", help="Checks if default password is used")
    parser_default.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_default.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_default.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_default.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_default.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_default.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_default.set_defaults(func=unpassworded_console)
    
    parser_brute = subparsers.add_parser("brute", help="Bruteforce")
    parser_brute.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_brute.add_argument("-cf", "--credential-file", type=str, help="Credential file")
    parser_brute.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_brute.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_brute.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_brute.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_brute.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_brute.set_defaults(func=brute_console)
    
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_post.add_argument("-u", "--username", type=str, default="postgres", help="Username (Default = postgres)")
    parser_post.add_argument("-p", "--password", type=str, default="", help="Username (Default = '')")
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