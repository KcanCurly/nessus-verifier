import smtplib
from src.utilities.utilities import confirm_prompt, get_hosts_from_file2, get_hosts_from_file, add_default_parser_arguments, error_handler
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass


def userenum_nv(hosts, domain, threads, timeout, errors, verbose):
    vuln = {}
    hosts = get_hosts_from_file(hosts)
    def check_enum(smtpp):
        try:
            answer = smtpp.docmd("VRFY", "test")
            if answer[0] == 250 or "unknown" in answer[1].decode().lower():
                if host not in vuln:
                    vuln[host] = []
                vuln[host].append("VRFY")
        except Exception as e:
            if errors: print(f"Error: {e}")
        
        try:
            answer = smtpp.docmd("EXPN", "test")
            if answer[0] == 250 or "unknown" in answer[1].decode().lower():
                if host not in vuln:
                    vuln[host] = []
                vuln[host].append("EXPN")
        except Exception as e:
            if errors: print(f"Error: {e}")
        
        try:
            answer = smtpp.docmd("MAIL FROM:", "test@test.com")
            if "STARTTLS" in answer[1].decode():
                smtp = smtplib.SMTP(ip, int(port), timeout=timeout)
                smtp.starttls()
                check_enum(smtp)
                return

            answer = smtpp.docmd("RCPT TO:", f"<a@{domain}>")
            if answer[0] == 250 or "unknown" in answer[1].decode().lower():
                if host not in vuln:
                    vuln[host] = []
                vuln[host].append("RCPT")
        except Exception as e:
            if errors: print(f"Error: {e}")
            
    for host in hosts:
        ip, port = host.split(":")
        try:
            smtp = smtplib.SMTP(ip, int(port), timeout=timeout)
            smtp.helo()
            check_enum(smtp)
        except Exception as e: # It could be that server requires TLS/SSL so we need to connect again with TLS
            try:
                smtp = smtplib.SMTP_SSL(ip, int(port), timeout=timeout)
                smtp.helo()
                check_enum(smtp)
            except Exception as e:
                if errors: print(f"Error: {e}")

    if len(vuln) > 0:
        print("User Enumeration Was Possible with Given Methods on Hosts:")
        for key, value in vuln.items():
            print(f"     {key} - {", ".join(value)}")
            

def sendmail(host, sender, receiver, subject, message):
    m = f'Subject: {subject}\n\n{message}'
    ip = host.ip
    port = host.port
    try:
        smtp = smtplib.SMTP(ip, port)
        smtp.sendmail(sender, receiver, m)
        return True
    except Exception: # It could be that server requires TLS/SSL so we need to connect again with TLS
        try:
            smtp = smtplib.SMTP_SSL(ip, port)
            smtp.sendmail(sender, receiver, m)
            return True
        except Exception:
            try:
                smtp = smtplib.SMTP(ip, port)
                smtp.starttls()
                smtp.sendmail(sender, receiver, m)
                return True
            except Exception: 
                pass
    return False
            
def userenum_console(args):
    userenum_nv(get_hosts_from_file(args.target), args.domain, args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):
    parser_task1 = commandparser.add_parser("smtp")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_userenum = subparsers.add_parser("userenum", help="Tries to enumerate users with VRFY EXPN and RCPT TO")
    parser_userenum.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_userenum.add_argument("domain", type=str, help="Domain name for RCPT TO")
    add_default_parser_arguments(parser_userenum, False)
    parser_userenum.set_defaults(func=userenum_console)
    
class SMTPOpenRelaySubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("openrelay", "Checks if the SMTP server is an open relay")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="File name or targets seperated by space")
        parser.add_argument("client1", type=str, help="Client email address 1")
        parser.add_argument("client2", type=str, help="Client email address 2")
        parser.add_argument("in_fake", type=str, help="Fake email address in domain")
        parser.add_argument("out_fake", type=str, help="Fake email address out of domain")
        parser.add_argument("out_real", type=str, help="Real email address out of domain")
        parser.add_argument("temp", type=str, help="Temporary email address")
        parser.add_argument("--subject", type=str, default="Openrelay Test", help="Email subject")
        parser.add_argument("--message", type=str, default="Openrelay test message", help="Email message, this is a template meaning $host would be replaced with the host value")
        parser.add_argument("--confirm", action="store_true", help="Bypass confirm prompt")
        add_default_parser_arguments(parser, False)
        parser.set_defaults(func=self.console)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), confirm=args.confirm, subject=args.subject, message=args.message, client1=args.client1, client2=args.client2, in_fake=args.in_fake, out_fake=args.out_fake, out_real=args.out_real, temp=args.temp)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        confirm = kwargs.get("confirm", False)
        subject = kwargs.get("subject")
        message = kwargs.get("message")
        client1 = kwargs.get("client1")
        client2 = kwargs.get("client2")
        in_fake = kwargs.get("in_fake")
        out_fake = kwargs.get("out_fake")
        out_real = kwargs.get("out_real")
        temp = kwargs.get("temp")


        if not confirm:
            print(f"Client1: {client1}")
            print(f"Client2: {client2}")
            print(f"In fake: {in_fake}")
            print(f"Fake out: {out_fake}")
            print(f"Real out: {out_real}")
            print(f"Temp: {temp}")
            print("Note: You can bypass this prompt by adding --confirm")
            if not confirm_prompt("Do you want to continue with those emails?"):
                return
        
        for host in hosts:
            if sendmail(host, client1, client1, subject, message):
                print(f"[+] Email sent from {client1} to {client1} on {host} successfully")
            if sendmail(host, client2, client1, subject, message):
                print(f"[+] Email sent from {client2} to {client1} on {host} successfully")
            if sendmail(host, in_fake, client1, subject, message):
                print(f"[+] Email sent from {in_fake} to {client1} on {host} successfully")
            if sendmail(host, out_real, client1, subject, message):
                print(f"[+] Email sent from {out_real} to {client1} on {host} successfully")
            if sendmail(host, client1, out_real, subject, message):
                print(f"[+] Email sent from {client1} to {out_real} on {host} successfully")
            if sendmail(host, in_fake, out_real, subject, message):
                print(f"[+] Email sent from {in_fake} to {out_real} on {host} successfully")
            if sendmail(host, out_fake, client1, subject, message):
                print(f"[+] Email sent from {out_fake} to {client1} on {host} successfully")
            if sendmail(host, out_fake, temp, subject, message):
                print(f"[+] Email sent from {out_fake} to {temp} on {host} successfully")


class SMTPServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("smtp")