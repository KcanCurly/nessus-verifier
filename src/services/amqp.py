import amqp.sasl
import i18n
from src.utilities.utilities import error_handler, generate_random_string, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import nmap
import amqp
import pika

import time
from pika import PlainCredentials, ConnectionParameters, BlockingConnection, exceptions


class RabbitMQConnection:
    _instance = None

    def __new__(cls, host="localhost", port=5672, username="admin", password="admin"):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, host="localhost", port=5672, username="admin", password="admin"):
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
        retries = 0
        while retries < 10:
            try:
                credentials = PlainCredentials(self.username, self.password)
                parameters = ConnectionParameters(host=self.host, port=self.port, credentials=credentials)
                self.connection = BlockingConnection(parameters)
                print("Connected to RabbitMQ")
                return
            except exceptions.AMQPConnectionError as e:
                print("Failed to connect to RabbitMQ:", e)

        print("Exceeded maximum number of connection retries. Stopping the code.")

    def is_connected(self):
        return self.connection is not None and self.connection.is_open

    def close(self):
        if self.is_connected():
            self.connection.close() # type: ignore
            self.connection = None
            print("Closed RabbitMQ connection")

    def get_channel(self):
        if self.is_connected():
            return self.connection.channel() # type: ignore

        return None


from rabbitmq_amqp_python_client import (  # PosixSSlConfigurationContext,; PosixClientCert,
    AddressHelper,
    AMQPMessagingHandler,
    Connection,
    Converter,
    Environment,
    Event,
    ExchangeSpecification,
    ExchangeToQueueBindingSpecification,
    Message,
    OutcomeState,
    QuorumQueueSpecification,
)

def create_connection(environment: Environment) -> Connection:
    connection = environment.connection()
    # in case of SSL enablement
    # ca_cert_file = ".ci/certs/ca_certificate.pem"
    # client_cert = ".ci/certs/client_certificate.pem"
    # client_key = ".ci/certs/client_key.pem"
    # connection = Connection(
    #    "amqps://guest:guest@localhost:5671/",
    #    ssl_context=PosixSslConfigurationContext(
    #        ca_cert=ca_cert_file,
    #        client_cert=ClientCert(client_cert=client_cert, client_key=client_key),
    #    ),
    # )
    connection.dial()

    return connection

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

        results = get_default_context_execution2("AMQP Default Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="deneme", password="deneme")

        if results:
            self.print_output(i18n.t('main.default_creds_title', name='AMQP'))
            for r in results:
                self.print_output(f"    {r}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        username=kwargs.get("username", "")
        password=kwargs.get("password", "")
        anonymous = kwargs.get("anonymous", False)
        try:
            conn = RabbitMQConnection(host.ip, int(host.port), "deneme", "deneme")
            conn.connect()
            print(conn.is_connected())
        except Exception as e: print("Error", e)

class AMQPVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)

        nm = nmap.PortScanner()
        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("AMQP Version", self.threads, hosts, self.single, nm=nm, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)

        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name='AMQP'))
            
            for key, value in versions.items():
                extra, pure_version = key.rsplit(" ", 1)

                cpe = ""
                cves = []
                if "rabbitmq" in key.lower():
                    cpe = f"cpe:2.3:a:vmware:rabbitmq:{pure_version}"
                if cpe:
                    if self.should_print_cves:
                        cves = get_cves(cpe)
                if cves: 
                    self.print_output(f"{extra} {pure_version} ({", ".join(cves)}):")
                else:
                    self.print_output(f"{extra} {pure_version}:")

                for v in value:
                    self.print_output(f"    {v}")

            if self.should_print_latest_version:
                latest_versions = self.parent_service.get_latest_version()
                if latest_versions:
                    self.print_output(f"Latest version for {self.parent_service.eol_product_name}")
                    for version in latest_versions:
                        self.print_output(version)



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
        self.eol_product_name = "rabbitmq"

        v = AMQPVersionSubServiceClass()
        v._set_parent(self)

        self.register_subservice(AMQPVersionSubServiceClass())
        self.register_subservice(AMQPDefaultCredsSubServiceClass())