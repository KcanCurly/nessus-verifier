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
    chars = string.ascii_letters + string.digits
    
    # Generate random string
    return ''.join(random.choice(chars) for _ in range(length))


class Listener2(stomp.ConnectionListener):
    def __init__(self, print_to_log=False):
        self.print_to_log = print_to_log
        self.z = 0


    def on_connecting(self, host_and_port):
        """
        :param (str,int) host_and_port:
        """
        print("on_connecting %s %s", *host_and_port)

    def on_connected(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        print("on_connected %s %s", frame.headers, frame.body)

    def on_disconnected(self):
        print("on_disconnected")

    def on_heartbeat_timeout(self):
        print("on_heartbeat_timeout")

    def on_before_message(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        print("on_before_message %s %s", frame.headers, frame.body)

    def on_message(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        print("on_message %s %s", frame.headers, frame.body)

    def on_receipt(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        print("on_receipt %s %s", frame.headers, frame.body)

    def on_error(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        print("on_error %s %s", frame.headers, frame.body)
        if "or password is invalid" in frame.body:
            print("P")
            self.z = 1

    def on_send(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        print("on_send", frame)
        if "DISCONNECT" in frame.cmd:
            print("D")
            self.z = 1

    def on_heartbeat(self):
        print("on_heartbeat")

class Listener(stomp.ConnectionListener):
    def __init__(self):
        self.z = 0

    def on_error(self, frame):
        print('received an error "%s"' % frame)
        print(frame.body)
        if "or password is invalid" in frame.body:
            self.z = 1
        
    def on_message(self, frame):
        print('received a message "%s"' % frame)

    def on_send(self, frame):
        print('sending a message "%s"' % frame)
        if "DISCONNECT" in frame.cmd:
            self.z = 1

class ActiveMQSSLSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("ssl", "Checks for SSL/TLS")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("ActiveMQ SSL Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output(i18n.t('main.non_tls_connection_accepted', name='ActiveMQ'))
            for r in results:
                self.print_output(f"    {r}")

    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        try:
            h = [(ip, port)]
            conn = stomp.Connection(host_and_ports=h)
            l = Listener2()
            conn.set_listener('', l)
            # conn.set_ssl(for_hosts=[(ip, port)])
            print(0)
            conn.connect("","",wait = True)
            time.sleep(1)
            print(1)
            conn.disconnect()
            print(2)
            time.sleep(1)
            print(3)
            if l.z == 1:
                print("1")
                return f"{host.ip}:{host.port}"
        except Exception as e: 
            print("Error", e)
            time.sleep(1)
            if l.z == 1:
                print("2")
                return f"{host.ip}:{host.port}"


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

        results = get_default_context_execution2("ActiveMQ Anonymous Access Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, anonymous=True)

        if results:
            self.print_output(i18n.t('main.anonymous_creds_title', name='ActiveMQ'))
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
        username=kwargs.get("username", "")
        password=kwargs.get("password", "")
        anonymous = kwargs.get("anonymous", False)
        try:
            h = [(ip, port)]
            conn = stomp.Connection(host_and_ports=h)
            if anonymous:
                conn.connect(wait = True)
            else:
                conn.connect(username, password, wait = True)
            conn.disconnect()
            
            return f"{host.ip}:{host.port}"
        except Exception as e: pass

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
        self.register_subservice(ActiveMQSSLSubServiceClass())