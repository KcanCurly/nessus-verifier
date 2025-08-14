import pymssql
import nmap
from src.utilities.utilities import Version_Vuln_Host_Data, get_cves, get_default_context_execution2, error_handler, get_hosts_from_file, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

version_mapping = {
"14.00.3490.00": "14.0.3490.10",
"14.00.3485.00": "14.0.3485.1",
"14.00.2070.00": "14.0.2070.1",
"14.00.3480.00": "14.0.3480.1",
"14.00.2065.00": "14.0.2065.1",
"14.00.3475.00": "14.0.3475.1",
"14.00.2060.00": "14.0.2060.1",
"14.00.3471.00": "14.0.3471.2",
"14.00.2056.00": "14.0.2056.2",
"14.00.3465.00": "14.0.3465.1",
"14.00.2052.00": "14.0.2052.1",
"14.00.3460.00": "14.0.3460.9",
"14.00.2047.00": "14.0.2047.8",
"14.00.3456.00": "14.0.3456.2",
"14.00.3451.00": "14.0.3451.2",
"14.00.3445.00": "14.0.3445.2",
"14.00.2042.00": "14.0.2042.3",
"14.00.3436.00": "14.0.3436.1",
"14.00.3430.00": "14.0.3430.2",
"14.00.3421.00": "14.0.3421.10",
"14.00.3411.00": "14.0.3411.3",
"14.00.3401.00": "14.0.3401.7",
"14.00.3391.00": "14.0.3391.2",
"14.00.3381.00": "14.0.3381.3",
"14.00.3370.00": "14.0.3370.1",
"14.00.2037.00": "14.0.2037.2",
"14.00.3356.00": "14.0.3356.20",
"14.00.3335.00": "14.0.3335.7",
"14.00.3294.00": "14.0.3294.2",
"14.00.3281.00": "14.0.3281.6",
"14.00.3257.00": "14.0.3257.3",
"14.00.3238.00": "14.0.3238.1",
"14.00.3223.00": "14.0.3223.3",
"14.00.3192.00": "14.0.3192.2",
"14.00.2027.00": "14.0.2027.2",
"14.00.3162.00": "14.0.3162.1",
"14.00.3103.00": "14.0.3103.1",
"14.00.2014.00": "14.0.2014.14",
"14.00.3076.00": "14.0.3076.1",
"14.00.3048.00": "14.0.3048.4",
"14.00.3045.00": "14.0.3045.24",
"14.00.3038.00": "14.0.3038.14",
"14.00.3037.00": "14.0.3037.1",
"14.00.2002.00": "14.0.2002.14",
"14.00.3035.00": "14.0.3035.2",
"14.00.3030.00": "14.0.3030.27",
"14.00.3029.00": "14.0.3029.16",
"14.00.3026.00": "14.0.3026.27",
"14.00.3025.00": "14.0.3025.34",
"14.00.3023.00": "14.0.3023.8",
"14.00.3022.00": "14.0.3022.28",
"14.00.3015.00": "14.0.3015.40",
"14.00.3015.00": "14.0.3015.40",
"14.00.2000.00": "14.0.2000.63",
"14.00.3008.00": "14.0.3008.27",
"14.00.3006.00": "14.0.3006.16",
"14.00.1000.00": "14.0.1000.169",
"15.00.4430.00": "15.0.4430.1",
"15.00.4420.00": "15.0.4420.2",
"15.00.4415.00": "15.0.4415.2",
"15.00.4410.00": "15.0.4410.1",
"15.00.2130.00": "15.0.2130.3",
"15.00.4405.00": "15.0.4405.4",
"15.00.4395.00": "15.0.4395.2",
"15.00.2125.00": "15.0.2125.1",
"15.00.4390.00": "15.0.4390.2",
"15.00.2120.00": "15.0.2120.1",
"15.00.4385.00": "15.0.4385.2",
"15.00.4382.00": "15.0.4382.1",
"15.00.2116.00": "15.0.2116.2",
"15.00.4375.00": "15.0.4375.4",
"15.00.4365.00": "15.0.4365.2",
"15.00.4360.00": "15.0.4360.2",
"15.00.2110.00": "15.0.2110.4",
"15.00.4355.00": "15.0.4355.3",
"15.00.4345.00": "15.0.4345.5",
"15.00.4335.00": "15.0.4335.1",
"15.00.4326.00": "15.0.4326.1",
"15.00.2104.00": "15.0.2104.1",
"15.00.4322.00": "15.0.4322.2",
"15.00.4316.00": "15.0.4316.3",
"15.00.4312.00": "15.0.4312.2",
"15.00.4298.00": "15.0.4298.1",
"15.00.4280.00": "15.0.4280.7",
"15.00.2101.00": "15.0.2101.7",
"15.00.4261.00": "15.0.4261.1",
"15.00.4249.00": "15.0.4249.2",
"15.00.4236.00": "15.0.4236.7",
"15.00.2095.00": "15.0.2095.3",
"15.00.4223.00": "15.0.4223.1",
"15.00.4198.00": "15.0.4198.2",
"15.00.4188.00": "15.0.4188.2",
"15.00.4178.00": "15.0.4178.1",
"15.00.4153.00": "15.0.4153.1",
"15.00.4138.00": "15.0.4138.2",
"15.00.4123.00": "15.0.4123.1",
"15.00.4102.00": "15.0.4102.2",
"15.00.4083.00": "15.0.4083.2",
"15.00.2080.00": "15.0.2080.9",
"15.00.4073.00": "15.0.4073.23",
"15.00.4063.00": "15.0.4063.15",
"15.00.4053.00": "15.0.4053.23",
"15.00.4043.00": "15.0.4043.16",
"15.00.4033.00": "15.0.4033.1",
"15.00.4023.00": "15.0.4023.6",
"15.00.4013.00": "15.0.4013.40",
"15.00.4003.00": "15.0.4003.23",
"15.00.2070.00": "15.0.2070.41",
"15.00.2000.00": "15.0.2000.5",
"16.00.4185.00": "16.0.4185.3",
"16.00.4175.00": "16.0.4175.1",
"16.00.4165.00": "16.0.4165.4",
"16.00.4155.00": "16.0.4155.4",
"16.00.1135.00": "16.0.1135.2",
"16.00.4150.00": "16.0.4150.1",
"16.00.1130.00": "16.0.1130.5",
"16.00.4145.00": "16.0.4145.4",
"16.00.4140.00": "16.0.4140.3",
"16.00.1125.00": "16.0.1125.1",
"16.00.4135.00": "16.0.4135.4",
"16.00.4131.00": "16.0.4131.2",
"16.00.1121.00": "16.0.1121.4",
"16.00.4125.00": "16.0.4125.3",
"16.00.4120.00": "16.0.4120.1",
"16.00.1115.00": "16.0.1115.1",
"16.00.4115.00": "16.0.4115.5",
"16.00.4105.00": "16.0.4105.2",
"16.00.4100.00": "16.0.4100.1",
"16.00.1110.00": "16.0.1110.1",
"16.00.4095.00": "16.0.4095.4",
"16.00.4085.00": "16.0.4085.2",
"16.00.4080.00": "16.0.4080.1",
"16.00.1105.00": "16.0.1105.1",
"16.00.4075.00": "16.0.4075.1",
"16.00.4065.00": "16.0.4065.3",
"16.00.4055.00": "16.0.4055.4",
"16.00.4045.00": "16.0.4045.3",
"16.00.4035.00": "16.0.4035.4",
"16.00.4025.00": "16.0.4025.1",
"16.00.4015.00": "16.0.4015.1",
"16.00.4003.00": "16.0.4003.1",
"16.00.1050.00": "16.0.1050.5",
"16.00.1000.00": "16.0.1000.6",
}

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

                pure_version  = version_mapping.get(pure_version, pure_version)

                key = key.rsplit(".", 1)[0]
                key = key.replace(".00.", ".0.")

                cves = []
                if "2019" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2019:{key}"
                elif "2017" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2017:{key}"
                elif "2022" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2022:{key}"
                elif "2016" in key:
                    cpe = f"cpe:2.3:a:microsoft:sql_server_2022:{key}"
                if cpe: 
                    cves = get_cves(cpe)
                if cves: 
                    self.print_output(f"{extra} {key} ({", ".join(cves)}):")
                else:
                    if not cpe:
                        self.print_output(f"{extra} {key} (EOL):")
                    else:
                        self.print_output(f"{extra} {key}:")

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
