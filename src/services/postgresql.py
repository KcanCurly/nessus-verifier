import argparse
import subprocess
import re
from impacket.smbconnection import SMBConnection
from src.utilities.utilities import get_hosts_from_file
from smb import SMBConnection as pysmbconn
from src.utilities.utilities import get_classic_single_progress, get_classic_overall_progress, get_classic_console, get_hosts_from_file
from rich.live import Live
from rich.progress import Progress, TaskID
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.services.service import Vuln_Data
from rich.console import Group
from rich.panel import Panel
import psycopg


def unpassworded_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
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
                                print(table[0])
                            print()
                except Exception as e: print(e)
            
        except Exception as e: print(e)

def unpassworded_console(args):
    unpassworded_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose, disable_visual_on_complete=args.disable_visual_on_complete)

def main():
    parser = argparse.ArgumentParser(description="PostgreSQL module of nessus-verifier.")
    
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    
    parser_default = subparsers.add_parser("default-password", help="Runs all modules")
    parser_default.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_default.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_default.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_default.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_default.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_default.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_default.set_defaults(func=unpassworded_console)
    
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()