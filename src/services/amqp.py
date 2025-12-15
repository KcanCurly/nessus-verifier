import i18n
from src.utilities.utilities import error_handler, generate_random_string, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass, VersionSubService
import nmap
from pika import PlainCredentials, ConnectionParameters, BlockingConnection, exceptions

class RabbitMQConnection:
    _instance = None

    def __new__(cls, host="localhost", port=5672, username="guest", password="guest"):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, host="localhost", port=5672, username="guest", password="guest"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def connect(self):
        try:
            credentials = PlainCredentials(self.username, self.password)
            parameters = ConnectionParameters(host=self.host, port=self.port, credentials=credentials)
            self.connection = BlockingConnection(parameters)
            return
        except exceptions.AMQPConnectionError as e:
            pass

    def is_connected(self):
        return self.connection is not None and self.connection.is_open

    def close(self):
        if self.is_connected():
            self.connection.close() # type: ignore
            self.connection = None

    def get_channel(self):
        if self.is_connected():
            return self.connection.channel() # type: ignore

        return None


class AMQPDefaultCredsSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("defaultcreds", "Checks for default credentials")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("AMQP Anonymous Access Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, anonymous=True)

        if results:
            self.print_output(i18n.t('main.anonymous_creds_title', name='AMQP'))
            for r in results:
                self.print_output(f"    {r}")

        for r in results:
            hosts.remove(r)

    @error_handler(["host"])
    def single(self, host, **kwargs):
        username=kwargs.get("username", "guest")
        password=kwargs.get("password", "guest")
        anonymous = kwargs.get("anonymous", False)
        try:
            conn = RabbitMQConnection(host.ip, int(host.port), username, password) # type: ignore
            conn.connect()
            if conn.is_connected():
                return host
        except Exception as e: print("Error", e)

class AMQPVersionSubServiceClass(VersionSubService):
    def __init__(self) -> None:
        super().__init__("version", "Checks version", [("RabbitMQ", "rabbitmq")])

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)

        nm = nmap.PortScanner()
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2(f"{self.products[0][0]} Version", self.threads, hosts, self.single, nm=nm, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            print(versions)
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name=self.products[0][0]))
            
            for key, value in versions.items():
                _, pure_version = key.rsplit(" ", 1)
                print(value)
                if "rabbitmq" in key.lower():
                    self.print_single_version_result("RabbitMQ", value, pure_version, "cpe:2.3:a:vmware:rabbitmq:")

            self.print_latest_versions()
            self.print_pocs()



    @error_handler(["host"])
    def single(self, host, **kwargs):
        nm:nmap.PortScanner = kwargs.get("nm") # type: ignore
        ip = host.ip
        port = host.port

        nm.scan(ip, port, arguments=f'--script amqp-info')
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'tcp' in nmap_host and int(port) in nmap_host['tcp']:
                tcp_info = nmap_host['tcp'][int(port)]
                product_name = None
                version_number = None
                product_name = tcp_info['product']
                version_number = tcp_info['version']
                z = product_name + " " + version_number
                return Version_Vuln_Host_Data(host, z)



class AMQPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("amqp")

        self.register_subservice(AMQPVersionSubServiceClass())
        self.register_subservice(AMQPDefaultCredsSubServiceClass())