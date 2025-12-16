import i18n
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc
from ejabberd_python3d.client import EjabberdAPIClient

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
            client = EjabberdAPIClient(host.ip,'admin','password', port=int(host.port))
            users = client.registered_users('kali')
            print(users)
        except Exception as e:
            print("Error", e)



class EjabberDServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ejabberd")
        self.register_subservice(EchoUsageSubServiceClass())
