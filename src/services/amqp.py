import i18n
from src.utilities.utilities import error_handler, generate_random_string, get_cves, get_default_context_execution2, Version_Vuln_Host_Data, nmap_identify_service_single
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

class AMQPVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        

        nm = nmap.PortScanner()
        results = get_default_context_execution2(f"AMQP Version", self.threads, hosts, self.single, nm=nm, timeout=self.timeout, errors=self.errors, verbose=self.verbose)


        version_dict = {}

        filtered = []

        for r in results:
            ip_port = r.split("=>")[0].strip()
            ver = r.split("=>")[1]
            if ver.strip() == "filtered":
                filtered.append(ip_port)
                continue
            if ver not in version_dict:
                version_dict[ver] = []
            version_dict[ver].append(ip_port)

        cve_set = set()



        if version_dict:
            version_dict = dict(sorted(version_dict.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name='AMQP'))
            for version, hosts in version_dict.items():
                cves = []
                if "rabbitmq" in version.lower():
                    _, pure_version, _ = version.strip().split(" ")
                    if self.should_print_cves:
                        cves = get_cves("cpe:2.3:a:broadcom:rabbitmq_server:" + pure_version)
                        cve_set.update(cves)
                    if cves:
                        self.print_output(f"RabbitMQ {pure_version}({', '.join(cves)}):")
                    else:
                        self.print_output(f"RabbitMQ {pure_version}:")
                else:
                    self.print_output(f"[Unknown] {version}:")
                for a in hosts:
                    self.print_output(f"    {a}")

            self.print_latest_versions("rabbitmq", "RabbitMQ")
            self.print_pocs(cve_set)

        if filtered:
            self.print_output(i18n.t('main.filtered_title'))
            for f in filtered:
                self.print_output(f"    {f}")



    @error_handler(["host"])
    def single(self, host, **kwargs):
        d = nmap_identify_service_single(host)
        if d:
            version = d["version"]
            if d["state"] == "filtered":
                return f"{host.ip}:{host.port} => filtered"
            else:
                return f"{host.ip}:{host.port} => {version}"


class AMQPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("amqp")

        self.register_subservice(AMQPVersionSubServiceClass())
        self.register_subservice(AMQPDefaultCredsSubServiceClass())