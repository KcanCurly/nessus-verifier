import stomp
import argparse
import time
from src.utilities.utilities import error_handler, get_cves, get_default_context_execution2, Version_Vuln_Host_Data
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
import nmap

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

def main():
    parser = argparse.ArgumentParser(description="ActiveMQ module of nessus-verifier.")
    
    subparsers = parser.add_subparsers(dest="command")  # Create subparsers
    
    parser_all = subparsers.add_parser("all", help="Runs all modules (Except post module")
    parser_all.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_all.add_argument("-u", "--username", type=str, default="postgres", help="Username (Default = postgres)")
    parser_all.add_argument("-p", "--password", type=str, default="", help="Username (Default = '')")
    parser_all.add_argument("--threads", default=10, type=int, help="Number of threads (Default = 10)")
    parser_all.add_argument("--timeout", default=5, type=int, help="Timeout in seconds (Default = 5)")
    parser_all.add_argument("--disable-visual-on-complete", action="store_true", help="Disables the status visual for an individual task when that task is complete, this can help on keeping eye on what is going on at the time")
    parser_all.add_argument("--only-show-progress", action="store_true", help="Only show overall progress bar")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_all.set_defaults(func=enumerate_console)
    
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

class ActiveMQVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("ActiveMQ Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                        
        if results:
            self.print_output("ActiveMQ Version:")               
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
        self.register_subservice(ActiveMQVersionSubServiceClass())