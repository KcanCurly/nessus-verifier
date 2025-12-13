import stomp
import argparse
import time
from src.utilities.utilities import error_handler, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import nmap
import i18n
from src.utilities.utilities import get_hosts_from_file

class Listener(stomp.ConnectionListener):
# Override the methods on_error and on_message provides by the
# parent class
    def on_error(self, headers, message):
        print('received an error "%s"' % message)# Print out the message received    def on_message(self, headers, message):
        
    def on_message(self, headers, message):
        print('received a message "%s"' % message)

def enumerate_nv(l: list[str], output: str = "", threads: int = 10, timeout: int = 3, verbose: bool = False, disable_visual_on_complete: bool = False):
    for host in l:
        ip = host.split(":")[0]
        port = host.split(":")[1]
        try:
            h = [(ip, int(port))]
            conn = stomp.Connection(h)
            conn.set_listener('', Listener())
            conn.connect('admin', 'admin', wait = True)
            conn.subscribe(destination='/queue/queue-1', id=1, ack='auto')
            time.sleep(5)
            conn.disconnect()
        except Exception as e: print(e)

def enumerate_console(args):
    enumerate_nv(get_hosts_from_file(args.file))

class ActiveMQVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("AMQP Scan", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                        
        if results:
            self.print_output(i18n.t('main.version_title', name='ActiveMQ'))
            for a in results:
                self.print_output(f"    {a}")


    @error_handler(["host"])
    def single(self, host, **kwargs):
        nm = nmap.PortScanner()
        ip = host.ip
        port = host.port
        nm.scan(ip, port, arguments=f'-sV')
        
        if ip in nm.all_hosts():
            nmap_host = nm[ip]
            if 'apachemq' in nmap_host['tcp'][int(port)]['name'].lower():
                product = nmap_host['tcp'][int(port)].get("product", "Service not found")
                version = nmap_host['tcp'][int(port)].get('version', '')
                return f"{host}{f" - {product} {version}" if product else ""}"



class AMQPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("activemq")
        self.eol_product_name = "apache-activemq"
        self.register_subservice(ActiveMQVersionSubServiceClass())