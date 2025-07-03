import subprocess
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class NFS_Vuln_Data():
    def __init__(self, host: str, content: dict[str, list[str]]):
        self.host = host
        self.content = content

showmount_cmd = ["showmount", "-e", "--no-headers"]
nfsls_cmd = ["nfs-ls", "nfs://"]

class NFSListServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("list", "List directories of nfs shares of the hosts")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[NFS_Vuln_Data] = get_default_context_execution2("NFS List", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output("Readable NFS List:")
            for r in results:
                self.print_output(r.host)
                for k,v in r.content.items():
                    self.print_output(f"    {k}:")
                    for n in v:
                        self.print_output(f"        {n}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        result = subprocess.run(showmount_cmd + [ip], text=True, capture_output=True)
        v = NFS_Vuln_Data(host, dict[str, list[str]]())
        for line in result.stdout.splitlines():
            c = ["nfs-ls", f"nfs://{ip}{line.split()[0]}"]
            result = subprocess.run(c, text=True, capture_output=True)
            v.content = dict[str, list[str]]()
            v.content[line.split()[0]] = []
            for line1 in result.stdout.splitlines():
                v.content[line.split()[0]].append(line1.rsplit(maxsplit=1)[1])

                
        if len(v.content.keys) > 1:  # type: ignore
            return v

class NFSServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("nfs")
        self.register_subservice(NFSListServiceClass())