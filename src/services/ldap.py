import subprocess
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class LDAPSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("anonymous", "Checks anonymous access")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results= get_default_context_execution2("LDAP Anonymous", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("LDAP anonymous access were found:")
            for v in results:
                self.print_output(f"    {v}")
            self.print_output("")
            self.print_output("Check with: ldapsearch -x -H ldap://<host> -b '' '(objectClass=*)'")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        command = ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "(objectClass=*)"]
        result = subprocess.run(command, text=True, capture_output=True)
        if "ldaperr" not in result.stdout.lower() and "can't contact" not in result.stderr.lower():
            return host

class LDAPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("ldap")
        self.register_subservice(LDAPSubServiceClass())