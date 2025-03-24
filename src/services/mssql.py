from src.utilities.utilities import get_hosts_from_file, add_default_parser_arguments
import pymssql
import nmap

def connect_to_server(ip, username, password, database, port, domain, login_timeout = 10):
    try:
        conn = pymssql.connect(ip, username, password, database, port=port, login_timeout=login_timeout)
    except Exception as e:
        try:
            conn = pymssql.connect(
                host=ip,
                user=f'{domain}\\{username}',
                password=password,
                database=database
            )      
        except Exception as e:
             return None
    return conn

def post_nv(hosts, username, password, domain, threads, timeout, errors, verbose):
    for host in hosts:
        try:
            ip, port = host.split(":")

            # Connect to SQL Server
            conn = connect_to_server(ip, username, password, "master", port, domain, login_timeout=10)
            if not conn: 
                if errors: print("Couldn't connect to", host)
                continue
            cursor = conn.cursor()

            try:
                # Get all databases
                cursor.execute("SELECT name FROM sys.databases")
                databases = [db[0] for db in cursor.fetchall()]

                for db in databases:
                    try:
                        cursor.execute(f"USE {db}")
                        print(f"\n[+] Processing database: {db}")
                        print("============================")
                        # Get all tables
                        cursor.execute("SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
                        tables = cursor.fetchall()


                        for schema, table in tables:
                            full_table_name = f"{schema}.{table}"
                            print(f"\n  [Schema: {schema}] [Table: {table}]")
                            print("----------------------------")
                            
                            try:
                                # Get all columns
                                cursor.execute(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table}'")
                                columns = [col[0] for col in cursor.fetchall()]
                                print(f"    Columns: {columns}")
                                
                                try:
                                    # Get first 5 rows
                                    cursor.execute(f"SELECT TOP 5 * FROM {full_table_name}")
                                    rows = cursor.fetchall()

                                    if rows:
                                        for row in rows:
                                            print("    Row:", row)
                                    else:
                                        print("    No data available")
                                except Exception as e: 
                                    if errors: print(f"Row Error: {host}: {e}")


                            except Exception as e: 
                                if errors: print(f"Column Error: {host}: {e}")
                            

                    except Exception as e: 
                        if errors: print(f"Table Error: {host}: {e}")
                    # Switch to the database

            except Exception as e:
                if errors: print(f"Database Error: {host}: {e}")


            # Close connection
            conn.close()
        except Exception as e: 
            if errors: print(f"Error for {host}: {e}")


        
def post_console(args):
    post_nv(get_hosts_from_file(args.target), args.username, args.password, args.domain, args.threads, args.timeout, args.errors, args.verbose)

def version_nv(hosts, threads, timeout, errors, verbose):
    versions = {}
    
    nm = nmap.PortScanner()
    for host in hosts:
        try:
            ip, port = host.split(":")

            nm.scan(ip, port, arguments=f'--script ms-sql-info')
            
            if ip in nm.all_hosts():
                nmap_host = nm[ip]
                if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                    tcp_info = nmap_host['tcp'][int(port)]
                    if 'script' in tcp_info and 'ms-sql-info' in tcp_info['script']:
                        # Extract the ms-sql-info output
                        ms_sql_info = tcp_info['script']['ms-sql-info']

                        # Parse the output to get product name and version
                        product_name = None
                        version_number = None

                        # Look for product and version in the output
                        for line in ms_sql_info.splitlines():
                            if "Product:" in line:
                                product_name = line.split(":")[1].strip()
                            if "number:" in line:
                                version_number = line.split(":")[1].strip()

                        # Print the results
                        if product_name and version_number:
                            z = product_name + " " + version_number
                            if z not in versions:
                                versions[z] = set()
                            versions[z].add(host)
        except Exception as e: pass #print(e)


    
    if len(versions) > 0:
        versions = dict(sorted(versions.items(), reverse=True))
        print("Detected MSSQL Versions:")
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"    {v}")

def version_console(args):
    version_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("mssql")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks version")
    add_default_parser_arguments(parser_version)
    parser_version.set_defaults(func=version_console)
    
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_post.add_argument("username", type=str, help="Username")
    parser_post.add_argument("password", type=str, help="Password")
    parser_post.add_argument("domain", type=str, help="Domain for windows authentication")
    add_default_parser_arguments(parser_post, False)
    parser_post.set_defaults(func=post_console)
