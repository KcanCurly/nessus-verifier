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
import pymssql

def post_nv(l: list[str], username: str, password: str, output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):

    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]

            # Connect to SQL Server
            conn = pymssql.connect(ip, username, password, "master", port=port, login_timeout=10)
            cursor = conn.cursor()

            try:
                # Get all databases
                cursor.execute("SELECT name FROM sys.databases")
                databases = [db[0] for db in cursor.fetchall()]
                print("[+] Databases:", databases)

                for db in databases:
                    print(f"\n[+] Processing database: {db}")
                    try:
                        cursor.execute(f"USE {db}")

                        # Get all tables
                        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
                        tables = [table[0] for table in cursor.fetchall()]
                        print(f"  Tables: {tables}")

                        for table in tables:
                            print(f"\n  [Table: {table}]")
                            try:
                                # Get all columns
                                cursor.execute(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table}'")
                                columns = [col[0] for col in cursor.fetchall()]
                                print(f"    Columns: {columns}")
                                
                                try:
                                    # Get first 10 rows
                                    cursor.execute(f"SELECT TOP 10 * FROM {table}")
                                    rows = cursor.fetchall()

                                    if rows:
                                        for row in rows:
                                            print("    Row:", row)
                                    else:
                                        print("    No data available")
                                except Exception as e: print(f"Row Error: {host}: {e}")


                            except Exception as e: print(f"Column Error: {host}: {e}")
                            

                    except Exception as e: print(f"Table Error: {host}: {e}")
                    # Switch to the database

            except Exception as e: print(f"Database Error: {host}: {e}")


            # Close connection
            conn.close()
        except Exception as e: print(f"Error for {host}: {e}")


        
def post_console(args):
    post_nv(get_hosts_from_file(args.file), args.username, args.password)


def version_nv(l: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    versions = {}
    
    for host in l:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]


            # Connect to SQL Server
            conn = pymssql.connect(ip, database="master", port=port, login_timeout=10)
            cursor = conn.cursor()

            # Execute version query
            cursor.execute("SELECT @@VERSION")
            version = cursor.fetchone()

            # Print the result
            print("[+] SQL Server Version:")
            print(version[0])

            # Close the connection
            conn.close()
        except Exception as e: print(f"Error for {host}: e")
    

                    
    versions = dict(sorted(versions.items(), reverse=True))
    if len(versions) > 0:       
        print("MSSQL versions detected:")                
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