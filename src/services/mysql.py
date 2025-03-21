from src.utilities.utilities import get_hosts_from_file
import nmap
import pymysql

def fetch_all_databases_and_tables(host, username, password):
    """Connects to MySQL, iterates over all databases, retrieves tables, and prints the first 10 rows."""
    try:
        # Connect to MySQL without selecting a database initially
        conn = pymysql.connect(
            host=host,
            user=username,
            password=password
        )
        cursor = conn.cursor()

        # Get list of all databases (excluding system databases)
        cursor.execute("SHOW DATABASES")
        databases = [db[0] for db in cursor.fetchall()]
        system_dbs = {"information_schema", "mysql", "performance_schema", "sys"}  # Ignore system DBs
        databases = [db for db in databases if db not in system_dbs]

        for db in databases:
            print(f"\n🔹 Scanning Database: {db}")

            # Switch to database
            cursor.execute(f"USE `{db}`")

            # Get list of all tables in the current database
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]

            for table in tables:
                print(f"\n  📌 Table: {table}")

                # Fetch first 10 rows
                cursor.execute(f"SELECT * FROM `{table}` LIMIT 10")
                rows = cursor.fetchall()

                # Get column names
                col_names = [desc[0] for desc in cursor.description]
                print("  " + " | ".join(col_names))  # Print header

                for row in rows:
                    print("  " + " | ".join(str(cell) for cell in row))

    except Exception as err:
        print(f"Error: {err}")

    finally:
        if conn:
            cursor.close()
            conn.close()

def post_nv(hosts: list[str], username: str, password: str, error:bool = False):
    for host in hosts:
        fetch_all_databases_and_tables(host, username, password)


        
def post_console(args):
    post_nv(get_hosts_from_file(args.file), args.username, args.password, args.errors)


def version_nv(hosts: list[str]):
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
    version_nv(get_hosts_from_file(args.file))

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("mysql")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks version")
    parser_version.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_version.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_version.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_version.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_version.set_defaults(func=version_console)
    
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_post.add_argument("-u", "--username", type=str, required=True, help="Username")
    parser_post.add_argument("-p", "--password", type=str, required=True, help="Password")
    parser_post.add_argument("-e", "--errors", action="store_true", help="Enable errors")
    parser_post.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_post.set_defaults(func=post_console)
