import i18n
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc
from pyejabberd import EjabberdAPIClient

class EchoUsageSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("usage", "Checks usage")

    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("Ejabberd Usage", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        
        if results:
            self.print_output(i18n.t('main.usage_title', name='Ejabberd'))
            for value in results:
                self.print_output(f"{value}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        try:
            client = EjabberdAPIClient(host=host.ip, port=int(host.port), username='admin', password='password', user_domain='kali',
                           protocol='https')

            users = client.registered_users('kali')
            print(users)
        except Exception as e:
            print("Error", e)



class EjabberDServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ejabberd")
        self.register_subservice(EchoUsageSubServiceClass())
