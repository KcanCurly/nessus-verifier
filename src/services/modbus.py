from src.utilities.utilities import error_handler, get_cves, get_default_context_execution2, nmap_identify_service_single
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import i18n
from pymodbus.client import ModbusTcpClient

class ActiveMQVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("enum", "Enumerate Modbus services and devices")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("Modbus Enumeration", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

    @error_handler(["host"])
    def single(self, host, **kwargs):
        client = ModbusTcpClient(host.ip, port=int(host.port))
        connection = client.connect()
        if connection:
            print("Connected to Modbus device")
        else:
            print("Failed to connect to Modbus device")




class ModbusServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("modbus")
        self.register_subservice(ActiveMQVersionSubServiceClass())
