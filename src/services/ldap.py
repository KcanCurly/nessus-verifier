import subprocess
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class LDAPSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("anonymous", "Checks anonymous access")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results= get_default_context_execution2("LDAP Anonymous", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print("LDAP anonymous access were found:")
            for v in results:
                print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port
        command = ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "(objectClass=*)"]
        result = subprocess.run(command, text=True, capture_output=True)
        if "ldaperr" not in result.stdout.lower():
            return host

class LDAPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ldap")
        self.register_subservice(LDAPSubServiceClass())