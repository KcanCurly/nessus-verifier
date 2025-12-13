import pprint
import i18n
from pymongo import MongoClient
import pymongo
from packaging.version import parse
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler, get_hosts_from_file, get_hosts_from_file2, add_default_serviceclass_arguments, Host, get_cves
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc

class MongoDBPostSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("post", "Post-exploit stuff")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("username", type=str, help="Username")
        parser.add_argument("password", type=str, help="Password")
        parser.add_argument("--sql", type=str, help="Run SQL on target")
        parser.add_argument("--databases", action="store_true", help="Print databases")
        parser.add_argument("--database", type=str, help="Select database")
        parser.add_argument("--collections", action="store_true", help="Print collections of selected database")
        parser.add_argument("--collection", type=str, help="Select collection")
        parser.add_argument("--fields", action="store_true", help="Print fields of selected collection")
        parser.add_argument("--field", nargs="+", help="Print values of selected fields")
        parser.add_argument("--limit", type=int, default=10, help="Row Limit (Default = 10)")
        add_default_serviceclass_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), username=args.username, password=args.password, sql=args.sql, limit=args.limit, 
                databases=args.databases, database=args.database, tables=args.collections, table=args.collection, 
                columns=args.fields, column=args.field, threads=args.threads, timeout=args.timeout, 
                errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        username = kwargs.get("username", 'postgres')
        password = kwargs.get("password", '')
        databases = kwargs.get('databases', False)
        database = kwargs.get('database', '')
        collections = kwargs.get('collections', False)
        collection = kwargs.get('collection', '')
        fields = kwargs.get('fields', False)
        field = kwargs.get('field', '')
        row_limit = kwargs.get("limit", 10)

        if (collections or collection) and not database:
            print("You need to select a database with argument --database")
            return
        
        if (fields or field) and not collection:
            print("You need to select a collection with argument --collection")
            return
        
        for host in hosts:
            try:
                ip = host.ip
                port = host.port
                client = MongoClient(ip, int(port), username=username, password=password)

                if databases:
                    dbs = client.list_databases()
                    for db in dbs:
                        self.print_output(f"Host: {host} - Database: {db['name']}")
                    return
                if collections:
                    db = client[database]
                    cols = d.list_collections()
                    for c in cols:
                        self.print_output(f"Host: {host} - Database: {db['name']} - Collection: {c['name']}")
                    return
                if fields:
                    _fields = set()
                    db = client[database]
                    coll = db[collection]
                    for c in coll.find(filter="", limit=1):
                        _fields.update(c.keys())
                    for k in _fields:
                        self.print_output(f"Host: {host} - Database: {db['name']} - Collection: {c['name']} - Field: {k}")
                    return
                
                if database and collection and field:
                    db = client[database]
                    doc = db[collection]
                    self.print_output(f"Host: {host} - Database: {db.name} - Collection: {doc.name}")
                    for c in doc.find(filter="", limit=row_limit):
                        pprint.pprint(c)
                    return
                
                dbs = client.list_databases()
                for db in dbs:
                    d = client[db["name"]]
                    cols = d.list_collections()
                    for c in cols:
                        doc = d[c["name"]]
                        self.print_output(f"Host: {host} - Database: {d.name} - Collection: {doc.name}")
                        for post in doc.find(filter="", limit=row_limit):
                            pprint.pprint(post)
                

            except Exception as e:
                if self.errors in [1, 2]:
                    print(f"Error Processing {host}: {e}")
                if self.errors == 2:
                    print_exc()


class MongoDB_Brute_Vuln_Data():
    def __init__(self, host: str, creds: list[str]):
        self.host = host
        self.creds = creds

class MongoDBBruteSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("brute", "Bruteforce")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("credential", type=str, help="File name or targets seperated by space, user:pass on each line")
        add_default_serviceclass_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), creds=get_hosts_from_file(args.credential), threads=args.threads, timeout=args.timeout, errors=args.errors, domain=args.domain, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        creds = kwargs.get("creds", [])
        domain = kwargs.get("domain", "")

        results: list[MongoDB_Brute_Vuln_Data] = get_default_context_execution2("MongoDB Brute", self.threads, hosts, self.single, creds=creds, domain=domain, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output("MongoDB Credentials Found on Hosts:")               
            for a in results:
                self.print_output(f"    {a.host} - {", ".join(a.creds)}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        creds = kwargs.get("creds", [])
        ip = host.ip
        port = host.port

        c = []

        for cred in creds:
            username, password = cred.split(":")
            _ = MongoClient(ip, int(port), username=username, password=password)
            c.append(f"{username}:{password}")
        
        if c:
            return MongoDB_Brute_Vuln_Data(f"{ip}:{port}", c)
        else:
            return None


class MongoDBUnauthSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("unauth", "Checks if unauthenticated access is allowed")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        vuln = []
        results: list[Host] = get_default_context_execution2("MongoDB Unauth Check", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            print("MongoDB Unauthenticated Access:")
            for v in results:
                print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        with pymongo.timeout(self.timeout):
            client = MongoClient(ip, int(port))
            dbs = client.list_databases()
            return host

class MongoDBVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("MongoDB Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:      
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output(i18n.t('main.version_title', name="MongoDB"))
            for key, value in versions.items():
                cves = []
                if self.print_cves:
                    cves = get_cves(f"cpe:2.3:a:mongodb:mongodb:{key}")
                if cves: self.print_output(f"MongoDB {key} ({", ".join(cves)}):")
                else: self.print_output(f"MongoDB {key}:")  
                for v in value:
                    self.print_output(f"    {v}")
            if self.print_latest_version:
                latest_versions = self.parent_service.get_latest_version()
                if latest_versions:
                    self.print_output(f"Latest version for {self.parent_service.eol_product_name}")
                    for version in latest_versions:
                        self.print_output(version)

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        with pymongo.timeout(self.timeout):
            client = MongoClient(ip, int(port))
            version = client.server_info()['version']
            return Version_Vuln_Host_Data(host, version)


class MongoDBServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("mongodb")
        self.eol_product_name = "mongodb"

        v = MongoDBVersionSubServiceClass()
        v._set_parent(self)

        self.register_subservice(v)
        self.register_subservice(MongoDBUnauthSubServiceClass())
        self.register_subservice(MongoDBPostSubServiceClass())
        self.register_subservice(MongoDBBruteSubServiceClass())