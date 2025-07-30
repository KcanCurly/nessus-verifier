import subprocess
from src.utilities.utilities import get_default_context_execution2, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class NFS_Vuln_Data():
    def __init__(self, host: str, content: str):
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
                self.print_output(f"{r.host}:")
                self.print_output(f"{r.content}")
                self.print_output("")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        showmount_result = subprocess.run(showmount_cmd + [ip], text=True, capture_output=True)
        v = NFS_Vuln_Data(f"{ip}:{port}", "")
        for line in showmount_result.stdout.splitlines():
            nfs_folder = line.split()[0]
            nfs_folder = nfs_folder.replace("/", "")
            c = ["nfs-ls", f"nfs://{ip}/{nfs_folder}"]

            nfsls_result = subprocess.run(c, text=True, capture_output=True)

            v.content = nfsls_result.stdout
                
        if v.content:  # type: ignore
            return v

class NFSServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("nfs")
        self.register_subservice(NFSListServiceClass())