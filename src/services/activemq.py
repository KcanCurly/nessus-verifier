import stomp
from stomp import PrintingListener
import time
from src.utilities.utilities import error_handler, get_cves, get_default_context_execution2, nmap_identify_service_single
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import i18n
from src.utilities.utilities import get_hosts_from_file
import random
import string

def generate_random_string(length=8):
    """
    Generate a random string of specified length using only ASCII letters and digits.
    """
    # Define the character pool: a-z, A-Z, 0-9
    chars = string.ascii_letters + string.digits  # 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    
    # Generate random string
    return ''.join(random.choice(chars) for _ in range(length))

class Listener(stomp.ConnectionListener):

    def on_error(self, headers, message):
        print('received an error "%s"' % message)
        
    def on_message(self, headers, message):
        print('received a message "%s"' % message)


class ActiveMQDefaultCredsSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("defaultcreds", "Checks for default credentials")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        
        results = get_default_context_execution2("ActiveMQ Random Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username=generate_random_string(), password=generate_random_string())

        if results:
            self.print_output(i18n.t('main.activemq_unauth_access', name='ActiveMQ'))
            for r in results:
                self.print_output(f"    {r}")

        for r in results:
            hosts.remove(r)

        results = get_default_context_execution2("ActiveMQ Default Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="system", password="manager")

        if results:
            self.print_output(i18n.t('main.default_creds_title', name='ActiveMQ'))
            for r in results:
                self.print_output(f"    {r}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        username=kwargs.get("username", "z")
        password=kwargs.get("password", "z")
        try:
            h = [(ip, port)]
            conn = stomp.Connection(host_and_ports=h)
            conn.set_listener('', PrintingListener())
            conn.connect(username, password, wait = True)
            conn.disconnect()
            return f"{host.ip}:{host.port}"
        except Exception as e: print(e)

class ActiveMQVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)
        
        cve_base = "cpe:2.3:a:apache:activemq:"

        results = get_default_context_execution2("ActiveMQ Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        version_dict = {}

        for r in results:
            ip_port = r.split("=>")[0].strip()
            version = r.split("=>")[1].split()[3].strip()
            if version not in version_dict:
                version_dict[version] = []
            version_dict[version].append(ip_port)

        cve_set = set()
                        
        if results:
            self.print_output(i18n.t('main.version_title', name='ActiveMQ'))
            for version, hosts in version_dict.items():
                cves = []
                if self.should_print_cves:
                    cves = get_cves(cve_base + version)
                    cve_set.update(cves)
                self.print_output(f"Apache ActiveMQ {version}{" (" + ''.join(cves) + ")"}:")
                for a in hosts:
                    self.print_output(f"    {a}")

            self.print_latest_versions("apache-activemq", "Apache ActiveMQ")
            self.print_pocs(cve_set)

    @error_handler(["host"])
    def single(self, host, **kwargs):
        d = nmap_identify_service_single(host)
        if d:
            version = d["version"]
            if version and version.startswith("ActiveMQ OpenWire transport"):
                return f"{host.ip}:{host.port} => {version}"



class AMQPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("activemq")
        self.eol_product_name = "apache-activemq"
        self.register_subservice(ActiveMQVersionSubServiceClass())
        self.register_subservice(ActiveMQDefaultCredsSubServiceClass())