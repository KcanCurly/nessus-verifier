import stomp
import time
from src.utilities.utilities import error_handler, generate_random_string, get_cves, get_default_context_execution2
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import i18n

class Listener(stomp.ConnectionListener):
    def __init__(self):
        self.z = 0

    def on_connected(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        self.z = 1

    def on_error(self, frame):
        """
        :param Frame frame: the stomp frame
        """
        if "or password is invalid" in frame.body:
            self.z = 1

class StompSSLSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("ssl", "Checks for SSL/TLS")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("Stomp SSL Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output(i18n.t('main.non_tls_connection_accepted', name='Stomp'))
            for r in results:
                self.print_output(f"    {r}")

    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port
        try:
            h = [(ip, port)]
            conn = stomp.Connection(host_and_ports=h)
            l = Listener()
            conn.set_listener('', l)
            # conn.set_ssl(for_hosts=[(ip, port)])
            conn.connect("","",wait = True)
            conn.disconnect()
            time.sleep(0.5)
            if l.z == 1:
                return f"{host.ip}:{host.port}"
        except Exception as e: 
            time.sleep(0.5)
            if l.z == 1:
                return f"{host.ip}:{host.port}"


class StompDefaultCredsSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("defaultcreds", "Checks for default credentials")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("Stomp Random Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username=generate_random_string(), password=generate_random_string())

        if results:
            self.print_output(i18n.t('main.activemq_unauth_access', name='Stomp'))
            for r in results:
                self.print_output(f"    {r}")

        for r in results:
            hosts.remove(r)

        results = get_default_context_execution2("Stomp Anonymous Access Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, anonymous=True)

        if results:
            self.print_output(i18n.t('main.anonymous_creds_title', name='Stomp'))
            for r in results:
                self.print_output(f"    {r}")

        for r in results:
            hosts.remove(r)

        results = get_default_context_execution2("Stomp Default Creds Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="system", password="manager")

        if results:
            self.print_output(i18n.t('main.default_creds_title', name='Stomp'))
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

class StompServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("stomp")

        self.register_subservice(StompDefaultCredsSubServiceClass())
        self.register_subservice(StompSSLSubServiceClass())