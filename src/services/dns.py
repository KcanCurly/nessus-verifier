import dns.query
import dns.message
import subprocess
import dns.rcode
import dns.resolver
import dns.reversename
import dns.update
import dns.zone
import re
from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_default_context_execution2, get_hosts_from_file2, add_default_parser_arguments
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from traceback import print_exc

def find_domain_name(ip):
    domain_name_pattern = r"PTR\s(.*?)\s+"
    try:
        command = ["dnsrecon", "-n", ip, "-t", "rvl", "-r", f"{ip}/31"]
        result = subprocess.run(command, capture_output=True, text=True)
        domain_match = re.search(domain_name_pattern, result.stdout)
        if domain_match and "in-addr.arpa" not in domain_match.group(1):
            domain = domain_match.group(1)
            domain = ".".join(domain.split(".")[1:])
            return domain
        else: return None # Couldn't find domain name
        
    except Exception as e:
        print("dnsrecon find domain name failed: ", e)
        return None
    

def add_txt_record_nv(hosts: list[str], txt_record_name, txt_record_value, error, verbose):
    vuln = []

    for host in hosts:
        ip, port = host.split(":")

        # If we don't have domain, we first need to get domain from ptr record
        try:
            reverse_name = dns.reversename.from_address(ip)
            
            # Perform the PTR query
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.port = int(port)  # Specify the port for the resolver
            
            answers = resolver.resolve(reverse_name, 'PTR')
            
            for rdata in answers:
                domain = rdata.to_text()
                parts = domain.split('.')
                domain = '.'.join(parts[-3:])
        except Exception as e:
            if error: print("Error: ", e)
            continue
        try:
            u = dns.update.Update(domain)
            u.add(txt_record_name, 3600, "TXT", txt_record_value)
            r = dns.query.tcp(u, ip, port=int(port))
            if dns.rcode.to_text(r.rcode()) == "NOERROR":
                vuln.append(host)
        except Exception as e:
            if error: print("Error: ", e)
        
    if len(vuln) > 0:
        print(f"'TXT' record named {txt_record_name} was added with value of '{txt_record_value}' on hosts:")
        for v in vuln:
            print(f"    {v}")


def cachepoison_nv(hosts: list[str], errors, verbose):
    vuln = []

    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            
            command = ["dig", f"@{ip}", "example.com"]
            result = subprocess.run(command, text=True, capture_output=True)
            answer = re.search("ANSWER: (.*), AUTHORITY", result.stdout)
            if answer:
                answer = int(answer.group(1))
                if answer > 0:
                    command = ["dig", f"@{ip}", "example.com", "+norecurse"]
                    result = subprocess.run(command, text=True, capture_output=True)
                    answer2 = re.search("ANSWER: (.*), AUTHORITY", result.stdout)
                    if answer2:
                        answer2 = int(answer2.group(1))
                        if answer == answer2:
                            vuln.append(host)
        except Exception as e:
            if errors:
                print("Error:", e)
        
    if len(vuln) > 0:
        print("Cache poison vulnerability detected on hosts:")
        for v in vuln:
            print(f"    {v}")
            
def add_txt_record_console(args):
    pass
    # add_txt_record_nv(get_hosts_from_file(args.file), args.name, args.value, args.errors, args.verbose)
    
def cachepoison_console(args):
    pass
    #cachepoison_nv(get_hosts_from_file(args.file), args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("dns")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_addtxtrecord = subparsers.add_parser("txt", help="Checks if we can add a txt record")
    parser_addtxtrecord.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_addtxtrecord.add_argument("-n", "--name", type=str, default="Pentest-TXT-Record", help="TXT Record name to be added (Default = Pentest-TXT-Record).")
    parser_addtxtrecord.add_argument("-nv", "--value", type=str, default="Pentest-TXT-Record-Value", help="TXT Record name to be added (Default = Pentest-TXT-Record-Value).")
    parser_addtxtrecord.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_addtxtrecord.add_argument("-v", "--verbose", action="store_true", help="Show Verbose")
    parser_addtxtrecord.set_defaults(func=add_txt_record_console)

    parser_cacheposion = subparsers.add_parser("cacheposion", help="Checks if cache can be posioned")
    parser_cacheposion.add_argument("-f", "--file", type=str, required=True, help="input file name")
    parser_cacheposion.add_argument("-e", "--errors", action="store_true", help="Show Errors")
    parser_cacheposion.add_argument("-v", "--verbose", action="store_true", help="Enable verbose")
    parser_cacheposion.set_defaults(func=cachepoison_console)

class DNSAnySubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("any", "Checks ANY query")
        
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        vuln = []

        for host in hosts:
            try:
                ip = host.ip
                port = host.port
                domain = find_domain_name(ip)
                if not domain: 
                    if errors: print("Couldn't found domain of the ip")
                    continue
                
                command = ["dig", "any", f"@{ip}", domain]
                result = subprocess.run(command, text=True, capture_output=True)
                answer = re.search("ANSWER: (.*), AUTHORITY", result.stdout)
                if answer:
                    answer = int(answer.group(1))
                    if answer > 0:
                        vuln.append(host)
                
            except Exception as e: 
                if errors: print("ANY function error: ", e)    
                        
        if len(vuln) > 0:
            print("Hosts that answered to 'ANY' query:")
            for v in vuln:
                print(f"    {v}")

class DNSVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results = get_default_context_execution2("DNS Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
                        
        if results:
            self.print_output("DNS Version:")               
            for a in results:
                self.print_output(f"    {a["ip"]}:{a["port"]} - {a["service"]} {a["version"]}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        result = subprocess.run(
            ["nmap", "-sV", "-p", port, "--version-all", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        for line in result.stdout.splitlines():
            if line.startswith(port):
                try:
                    parts = line.split(maxsplit=3)
                    if parts[1] == "open":
                        return {
                            "ip": ip,
                            "port": port,
                            "protocol": parts[0].split("/")[1],
                            "service": parts[2],
                            "version": parts[3]
                        }
                except:
                    parts = line.split(maxsplit=2)
                    if parts[1] == "open":
                        return {
                            "ip": ip,
                            "port": port,
                            "protocol": parts[0].split("/")[1],
                            "service": parts[2],
                            "version": ""
                        }

class DNSAddDNSSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("adddns", "Checks if we can add a dns record")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("domain", type=str, help="File name or targets seperated by space")
        parser.add_argument("-n", "--name", type=str, default="Pentest-TXT-Record", help="TXT Record name to be added (Default = Pentest-TXT-Record).")
        parser.add_argument("-nv", "--value", type=str, default="Pentest-TXT-Record-Value", help="TXT Record name to be added (Default = Pentest-TXT-Record-Value).")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)
        
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("verbose", DEFAULT_VERBOSE)
        domain = kwargs.get("domain", "")
        txt_record_name = kwargs.get("name", "")
        txt_record_value  = kwargs.get("value", "")
        vuln = []
        for host in hosts:
            ip = host.ip
            port = host.port

            try:
                u = dns.update.UpdateMessage(domain)
                u.add(txt_record_name, 3600, "TXT", f'"{txt_record_value}"')
                r = dns.query.tcp(u, ip, port=int(port))
                print(r)
                if dns.rcode.to_text(r.rcode()) == "NOERROR":
                    vuln.append(host)
            except Exception as e:
                if errors: print("Error: ", e)
                        
        if len(vuln) > 0:
            print(f"'TXT' record named {txt_record_name} was added with value of '{txt_record_value}' on hosts:")
            for v in vuln:
                print(f"    {v}")

class DNSRecursionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("recursion", "Checks if recursion is enabled")
        
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        vuln = []
        for host in hosts:
            ip = host.ip
            port = host.port

            # If we don't have domain, we first need to get domain from ptr record
            domain = find_domain_name(ip)
            if not domain: 
                if errors: print("Couldn't found domain of the ip")
                continue

            try:
                command = ["dnsrecon", "-n", ip, "-d", domain]
                result = subprocess.run(command, capture_output=True, text=True)
                if "Recursion enabled on" in result.stdout:
                    vuln.append(host)
            except Exception as e:
                if errors: print("Error:", e)

        
        if len(vuln) > 0:
            print("Recursion is ENABLED on Hosts:")
            for v in vuln:
                print(f"    {v}")

class DNSAXFRSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("axfr", "Checks if zone transfer is possible")
        
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        vuln = []
        for host in hosts:
            ip = host.ip
            port = host.port

            # If we don't have domain, we first need to get domain from ptr record
            domain = find_domain_name(ip)
            if not domain:
                if errors: print("Couldn't found domain of the ip")
                continue

            try:
                command = ["dnsrecon", "-n", ip, "-a", "-d", domain]
                result = subprocess.run(command, capture_output=True, text=True)
                if "Zone Transfer was successful" in result.stdout:
                    vuln.append(host)
                    

            except Exception as e: 
                if errors: print("Error: ", e)
                
        if len(vuln) > 0:
            print("Zone Transfer Was Successful on Hosts:")
            for v in vuln:
                print(f"    {v}") 
    
class DNSSecSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("dnssec", "Checks if dnssec is enabled")
        
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        vuln = []
        for host in hosts:
            ip = host.ip
            port = host.port

            # If we don't have domain, we first need to get domain from ptr record

            domain = find_domain_name(ip)
            if not domain:
                if errors: print("Couldn't found domain of the ip")
                continue

            try:
                command = ["dnsrecon", "-n", ip, "-d", domain]
                result = subprocess.run(command, capture_output=True, text=True)
                if "DNSSEC is not configured" in result.stdout:
                    vuln.append(host)
                    
            except Exception as e: 
                if errors: print("Error:", e)
            
        if len(vuln) > 0:
            print("DNSSEC is NOT configured on Hosts:")
            for v in vuln:
                print(f"    {v}")

class DNSMaliciousSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("malicious", "Checks if malicious domain can be resolved")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("--domains", nargs="+", default=["accounts.googleaccesspoint.com", "86-adm.one", "pvkxculusei.xyz"], help="List of malicious domains seperated by space")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), domains=args.domains, threads=args.threads, timeout=args.timeout, 
                errors=args.errors, verbose=args.verbose)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        domains = kwargs.get("domains", ["accounts.googleaccesspoint.com", "86-adm.one", "pvkxculusei.xyz"])
        vuln = []
        for host in hosts:
            ip = host.ip
            port = host.port

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]  # Set the specific DNS server
            for malicious_domain in domains:
                try:
                    answers = resolver.resolve(malicious_domain, "A")  # Query for A record
                    for answer in answers:
                        vuln.append(f"{host} resolves to {malicious_domain}: {answer}".strip())
                except Exception as e:
                    if errors in [1, 2]:
                        print(f"Error resolving {malicious_domain} on {host}: {e}")
                    if errors == 2:
                        print_exc()

        if vuln:
            sorted_vuln = sorted(vuln)
            print(f"Host that were able to resolve malicious domains:")
            for v in sorted_vuln:
                print(f"    {v}")



class DNSServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("dns")
        self.register_subservice(DNSMaliciousSubServiceClass())
        self.register_subservice(DNSSecSubServiceClass())
        self.register_subservice(DNSAXFRSubServiceClass())
        self.register_subservice(DNSRecursionSubServiceClass())
        self.register_subservice(DNSAnySubServiceClass())
        self.register_subservice(DNSAddDNSSubServiceClass())
        self.register_subservice(DNSVersionSubServiceClass())