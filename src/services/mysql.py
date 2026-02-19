import i18n
import nmap
import pymysql
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler, get_hosts_from_file2, add_default_serviceclass_arguments
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
        add_default_serviceclass_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), username=args.username, password=args.password, sql=args.sql, limit=args.limit, 
                databases=args.databases, database=args.database, tables=args.tables, table=args.table, 
                columns=args.columns, column=args.column, threads=args.threads, timeout=args.timeout, 
                errors=args.errors, verbose=args.verbose)
        


    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

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
            try:
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
                _databases = [db[0] for db in cursor.fetchall()]
                _databases = [db for db in _databases if db not in system_dbs]

                if databases:
                    for db in _databases:
                        print(f"Host: {host} - Database: {db}")
                    return
                if tables:
                    if database not in _databases:
                        print(f"Database {database} not found")
                        return
                    cursor.execute("""
                        SELECT table_name 
                        FROM information_schema.tables 
                        WHERE table_schema = %s
                    """, (database,))

                    tables = cursor.fetchall()
                    for table in tables:
                        print(f"Host: {host} - Database: {database} - Table - {table[0]}")
                    return
                
                if columns:
                    if database not in _databases:
                        print(f"Database {database} not found")
                        return
                    cursor.execute(f"USE `{database}`")
                    cursor.execute(f"SHOW COLUMNS FROM `{table}`")
                    columns = cursor.fetchall()
                    
                    for col in columns:
                        print(f"Host: {host} - Database: {database} - Table - {table} - Column: {col[0]}")
                    return

                if database and table and column:
                    if database not in _databases:
                        print(f"Database {database} not found")
                        return
                    cursor.execute(f"USE `{database}`")
                    cursor.execute(f"SELECT {', '.join(column)} FROM `{table}` LIMIT {row_limit}")
                    rows = cursor.fetchall()
                    print(f"Host: {host} - Database: {database} - Table - {table} - Columns: {', '.join(column)}")
                    for row in rows:
                        print(row)
                    return
                
                for db in _databases:
                    print(f"\n=== Database: {db} ===")
                    cursor.execute(f"USE `{db}`")
                    try:
                        # Get tables via information_schema
                        cursor.execute("""
                            SELECT table_name 
                            FROM information_schema.tables 
                            WHERE table_schema = %s
                        """, (db,))
                        tables = [t[0] for t in cursor.fetchall()]

                        for table in tables:
                            print(f"\n--- Table: {table} ---")
                            try:
                                cursor.execute(f"SELECT * FROM `{db}`.`{table}` LIMIT 10")
                                rows = cursor.fetchall()
                                headers = [desc[0] for desc in cursor.description]
                                print(" | ".join(headers))
                                print(f"Host: {host} - Database: {db} - Table - {table}")
                                for row in rows:
                                    print(" | ".join(str(cell) for cell in row))
                            except Exception as e:
                                pass
                                # print(f"[!] Error reading table {db}.{table}: {e}")
                    except Exception as e:
                        pass
                        # print(f"[!] Error listing tables in database {db}: {e}")
            except Exception as e:
                pass
                    
class MYSQLVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("MySQL Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = []
            versions[r.version].append(r.host)

        
        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name="MySQL"))
            for key, value in versions.items():
                self.print_output(f"{key}:")
                for v in value:
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
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

class MySQLServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mysql")
        self.register_subservice(MYSQLVersionSubServiceClass())
        self.register_subservice(MYSQLPostSubServiceClass())