import pymssql
import nmap
from src.utilities.utilities import Version_Vuln_Host_Data, get_cves, get_default_context_execution2, error_handler, get_hosts_from_file, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

def connect_to_server(ip, username, password, database, port, domain, login_timeout = 10):
    try:
        conn = pymssql.connect(ip, username, password, database, port=port, login_timeout=login_timeout)
    except Exception:
        try:
            conn = pymssql.connect(ip, username, password, database, port=port, login_timeout=login_timeout, tds_version="7.0")
        except Exception:
            try:
                conn = pymssql.connect(
                    host=ip,
                    user=f'{domain}\\{username}',
                    password=password,
                    database=database
                )
            except Exception:
                return None
    return conn

class MSSQL_Brute_Vuln_Data():
    def __init__(self, host: str, creds: list[str]):
        self.host = host
        self.creds = creds

class MSSQLBruteSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Bruteforce")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("credential", type=str, help="File name or targets seperated by space, user:pass on each line")
        parser.add_argument("--domain", default="a", type=str, help="Domain for windows authentication")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), creds=get_hosts_from_file(args.credential), threads=args.threads, timeout=args.timeout, errors=args.errors, domain=args.domain, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        creds = kwargs.get("creds", [])
        domain = kwargs.get("domain", "")

        results: list[MSSQL_Brute_Vuln_Data] = get_default_context_execution2("MSSQL Brute", self.threads, hosts, self.single, creds=creds, domain=domain, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output("MSSQL Credentials Found on Hosts:")               
            for a in results:
                self.print_output(f"    {a.host} - {", ".join(a.creds)}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        creds = kwargs.get("creds", [])
        domain = kwargs.get("domain", "")
        ip = host.ip
        port = host.port

        c = []

        for cred in creds:
            username, password = cred.split(":")
            if connect_to_server(ip, username, password, "master", str(port), domain, login_timeout=10):
                c.append(f"{username}:{password}")
        
        if c:
            return MSSQL_Brute_Vuln_Data(f"{ip}:{port}", c)
        else:
            return None



class MSSQLPostSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("post", "Post-exploit stuff")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("username", type=str, help="Username")
        parser.add_argument("password", type=str, help="Password")
        parser.add_argument("--domain", default="a", type=str, help="Domain for windows authentication")
        parser.add_argument("--databases", action="store_true", help="Print databases")
        parser.add_argument("--database", type=str, help="Select database")
        parser.add_argument("--tables", action="store_true", help="Print tables of selected database")
        parser.add_argument("--table", type=str, help="Select table")
        parser.add_argument("--columns", action="store_true", help="Print columns of selected table")
        parser.add_argument("--column", nargs="+", help="Print values of selected columns")
        parser.add_argument("--limit", type=int, default=10, help="Row Limit (Default = 10)")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), username=args.username, password=args.password, domain=args.domain, limit=args.limit, 
                databases=args.databases, database=args.database, tables=args.tables, table=args.table, 
                columns=args.columns, column=args.column, threads=args.threads, timeout=args.timeout, 
                errors=args.errors, verbose=args.verbose)
        
    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        username = kwargs.get("username", 'postgres')
        password = kwargs.get("password", '')
        domain = kwargs.get("domain", "")
        sql = kwargs.get('sql', '')
        databases = kwargs.get('databases', False)
        database = kwargs.get('database', '')
        tables = kwargs.get('tables', False)
        table = kwargs.get('table', '')
        columns = kwargs.get('columns', False)
        column = kwargs.get('column', '')
        row_limit = kwargs.get("limit", 10)
        if (tables or table) and not database:
            print("You need to select a database with argument --database")
            return
        
        if (column or columns) and not table:
            print("You need to select a table with argument --table")
            return
        
        for host in hosts:
            try:
                ip = host.ip
                port = host.port

                # Connect to SQL Server
                conn = connect_to_server(ip, username, password, "master", str(port), domain, login_timeout=10)
                """
                if not conn: 
                    if errors: print("Couldn't connect to", host)
                    continue
                """
                cursor = conn.cursor() # type: ignore

                if sql:
                    cursor.execute(sql)
                    rows = cursor.fetchall()
                    if rows:
                        for row in rows:
                            self.print_output(row)
                    else:
                        self.print_output("No data available")
                    return
                
                if databases:
                    cursor.execute("SELECT name FROM sys.databases")
                    databases = [db[0] for db in cursor.fetchall()] # type: ignore
                    for db in databases:
                        self.print_output(f"Host: {host} - Database: {db}")

                    return

                if tables:
                    cursor.execute(f"USE {database}")
                    cursor.execute("SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
                    tables = cursor.fetchall()
                    for schema, table in tables: # type: ignore
                        self.print_output(f"Host: {host} - Database: {database} - Table: {table} - Schema: {schema}")
                    return

                if columns:
                    cursor.execute(f"USE {database}")
                    cursor.execute(f"SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table}'")
                    columns = [(col[0], col[1]) for col in cursor.fetchall()] # type: ignore
                    for column, data_type in columns:
                        self.print_output(f"Host: {host} - Database: {database} - Table: {table} - Column: {column} - ColumnType: {data_type}")
                    return
                
                if database and table and column:
                    cursor.execute(f"USE {database}")
                    cursor.execute(f"SELECT TOP {row_limit} {', '.join(column)} FROM {table}")
                    rows = cursor.fetchall()
                    self.print_output(f"Host: {host} - Database: {database} - Table: {table} - Columns: {', '.join(column)}")
                    if rows:
                        for row in rows:
                            self.print_output(row)
                    else:
                        self.print_output("No data available")
                    return

                try:
                    # Get all databases
                    cursor.execute("SELECT name FROM sys.databases")
                    databases = [db[0] for db in cursor.fetchall()] # type: ignore

                    for db in databases:
                        try:
                            cursor.execute(f"USE {db}")
                            # Get all tables
                            cursor.execute("SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
                            tables = cursor.fetchall()


                            for schema, table in tables: # type: ignore
                                full_table_name = f"{schema}.{table}"
                                try:
                                    # Get all columns
                                    cursor.execute(f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table}'")
                                    columns = [col[0] for col in cursor.fetchall()] # type: ignore
                                    
                                    try:
                                        # Get first 5 rows
                                        cursor.execute(f"SELECT TOP {row_limit} * FROM {full_table_name}")
                                        rows = cursor.fetchall()
                                        self.print_output(f"Host: {host} - Database: {db} - Table: {table} - Columns: {', '.join(columns)}")
                                        if rows:
                                            for row in rows:
                                                self.print_output(row)
                                        else:
                                            self.print_output("No data available")
                                    except Exception as e: 
                                        if self.errors: print(f"Row Error: {host}: {e}")


                                except Exception as e: 
                                    if self.errors: print(f"Column Error: {host}: {e}")
                                

                        except Exception as e: 
                            if self.errors: print(f"Table Error: {host}: {e}")

                except Exception as e:
                    if self.errors: print(f"Database Error: {host}: {e}")

                conn.close() # type: ignore
            except Exception as e: 
                if self.errors: print(f"Error for {host}: {e}")


class MSSQLVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("MSSQL Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        versions = {}
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output("Detected MSSQL Versions:")
            

            for key, value in versions.items():
                extra, pure_version = key.rsplit(" ", 1)

                cpe = ""



                z = pure_version.rsplit(".", 1)[0]
                z = z.replace(".00.", ".0.")

                cves = []
                if "2019" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2019:{z}"
                elif "2017" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2017:{z}"
                elif "2022" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2022:{z}"
                elif "2016" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2022:{z}"
                if cpe: 
                    cves = get_cves(cpe)
                if cves: 
                    self.print_output(f"{extra} {pure_version} ({", ".join(cves)}):")
                else:
                    if not cpe:
                        self.print_output(f"{extra} {pure_version} (EOL):")
                    else:
                        self.print_output(f"{extra} {pure_version}:")

                for v in value:
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        nm = nmap.PortScanner()
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
                        return Version_Vuln_Host_Data(host, z)


class MSSQLServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mssql")
        self.register_subservice(MSSQLVersionSubServiceClass())
        self.register_subservice(MSSQLPostSubServiceClass())
        self.register_subservice(MSSQLBruteSubServiceClass())
