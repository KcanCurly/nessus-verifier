import i18n
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc
from pyejabberd import EjabberdAPIClient
import xmpp

class EchoUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        #results = get_default_context_execution2("Ejabberd Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="admin", password="password", domain="kali")
        results = get_default_context_execution2("Ejabberd Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, username="admin", password="b<35b3w", domain="kali")
        
        if results:
            self.print_output(i18n.t('main.usage_title', name='Ejabberd'))
            for value in results:
                self.print_output(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        username=kwargs.get("username", "")
        password=kwargs.get("password", "")
        domain=kwargs.get("domain", "")
        
        jabberid = username + "@" + domain
        receiver = "bazqux@xmpp.domain.tld"
        message  = "hello world"
        try:
            jid = xmpp.protocol.JID(jabberid)
            print("1")
            connection = xmpp.Client(server=jid.getDomain())

            print("2")
            connection.connect((host.ip, host.port))
            print(connection.isConnected())
            connection.debug_flags

            print("3")
            connection.auth(user=jid.getNode(), password=password, resource=jid.getResource())
            print("4")
        except xmpp.protocol.HostUnknown as e:
            print("Wrong Domain")
        except Exception as e:
            print("Error", e)


class EjabberDServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ejabberd")
        self.register_subservice(EchoUsageSubServiceClass())
