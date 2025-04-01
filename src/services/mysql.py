import nmap
import pymysql
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class MYSQLPostSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("post", "Post-exploit stuff")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("username", type=str, default="root", help="Username (Default = root)")
        parser.add_argument("password", type=str, default="", help="Username (Default = '')")
        parser.add_argument("--sql", type=str, help="Run SQL on target")
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
        self.nv(get_hosts_from_file2(args.target), username=args.username, password=args.password, sql=args.sql, limit=args.limit, 
                databases=args.databases, database=args.database, tables=args.tables, table=args.table, 
                columns=args.columns, column=args.column, threads=args.threads, timeout=args.timeout, 
                errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        username = kwargs.get("username", 'postgres')
        password = kwargs.get("password", '')
        sql = kwargs.get('sql', '')
        databases = kwargs.get('databases', False)
        database = kwargs.get('database', '')
        tables = kwargs.get('tables', False)
        table = kwargs.get('table', '')
        columns = kwargs.get('columns', False)
        column = kwargs.get('column', '')
        row_limit = kwargs.get("limit", 10)

        system_dbs = {"information_schema", "mysql", "performance_schema", "sys"}  # Ignore system DBs

        if (tables or table) and not database:
            print("You need to select a database with argument --database")
            return
        
        if (column or columns) and not table:
            print("You need to select a table with argument --table")
            return

        for host in hosts:
            conn = None
            cursor = None
            ip = host.ip
            port = host.port

            conn = pymysql.connect(
                host=ip,
                user=username,
                password=password,
                port=int(port)
            )
            cursor = conn.cursor()

            if sql:
                cursor.execute(sql)
                rows = cursor.fetchall()
                for row in rows:
                    print(row)
                return

            # Get list of all databases (excluding system databases)
            cursor.execute("SHOW DATABASES")
            databases = [db[0] for db in cursor.fetchall()]
            databases = [db for db in databases if db not in system_dbs]

            if databases:
                for db in databases:
                    print(db)
                return
            if tables:
                if database not in databases:
                    print(f"Database {database} not found")
                    return
                cursor.execute(f"USE `{database}`")
                cursor.execute("SHOW TABLES")
                tables = [table[0] for table in cursor.fetchall()]
                if tables:
                    for t in tables:
                        print(t)
                else:
                    print(f"No tables found in database {database}")
                return
            
            if columns:
                if database not in databases:
                    print(f"Database {database} not found")
                    return
                cursor.execute(f"USE `{database}`")
                cursor.execute("SHOW TABLES")
                tables = [table[0] for table in cursor.fetchall()]
                if table not in tables:
                    print(f"Table {table} not found in database {database}")
                    return
                cursor.execute(f"DESCRIBE {table}")
                columns = [(col[0], col[1]) for col in cursor.fetchall()]
                if columns:
                    for c in columns:
                        print(f"{c[0]}: {c[1]}")

            if database and table and column:
                if database not in databases:
                    print(f"Database {database} not found")
                    return
                cursor.execute(f"USE `{database}`")
                cursor.execute("SHOW TABLES")
                tables = [table[0] for table in cursor.fetchall()]
                if table not in tables:
                    print(f"Table {table} not found in database {database}")
                    return
                cursor.execute(f"SELECT {', '.join(column)} FROM `{table}` LIMIT {row_limit}")
                rows = cursor.fetchall()
                for row in rows:
                    print(row)
                return
            
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
                    cursor.execute(f"SELECT * FROM `{table}` LIMIT {row_limit}")
                    rows = cursor.fetchall()

                    # Get column names
                    col_names = [desc[0] for desc in cursor.description]
                    print("  " + " | ".join(col_names))  # Print header

                    for row in rows:
                        print("  " + " | ".join(str(cell) for cell in row))


    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

class MYSQLVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("MySQL Version", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = []
            versions[r.version].append(r.host)

        
        if len(versions) > 0:
            versions = dict(sorted(versions.items(), reverse=True))
            print("Detected MySQL Versions:")
            for key, value in versions.items():
                print(f"{key}:")
                for v in value:
                    print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        nm = nmap.PortScanner()

        nm.scan(ip, port, arguments=f'--script mysql-info')
        
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                tcp_info = nmap_host['tcp'][int(port)]
                if 'script' in tcp_info and 'mysql-info' in tcp_info['script']:
                    # Extract the mysql-info output
                    ms_sql_info = tcp_info['script']['mysql-info']

                    # Parse the output to get product name and version
                    product_name = None
                    # Look for product and version in the output
                    for line in ms_sql_info.splitlines():
                        if "Version:" in line:
                            product_name = line.split(":")[1].strip()

                    # Print the results
                    if product_name:
                        return Version_Vuln_Host_Data(host, product_name)

class PSQLServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mysql")
        self.register_subservice(MYSQLVersionSubServiceClass())
        self.register_subservice(MYSQLPostSubServiceClass())