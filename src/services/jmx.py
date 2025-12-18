import re
import subprocess
import requests
import i18n
from src.utilities.utilities import add_default_serviceclass_arguments, error_handler, get_default_context_execution2, Version_Vuln_Host_Data, get_header_from_url, get_hosts_from_file2, get_url_response
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass, VersionSubService
import requests
import jmxquery
from enum import Enum

class PREDEFINED_QUERY(Enum):
    TOMCAT_SERVER_INFO = "Tomcat Server Info"

q = {
    PREDEFINED_QUERY.TOMCAT_SERVER_INFO: ("Catalina:type=Server", "serverInfo")
}

class JMXQuerySubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("query", "JMX Query")

    def helper_parse(self, subparsers):
        parser_enum = subparsers.add_parser(self.command_name, help = self.help_description)
        add_default_serviceclass_arguments(parser_enum)
        parser_enum.set_defaults(func=self.console)
        parser_enum.add_argument("--username", type=str, required=False, help="Username")
        parser_enum.add_argument("--password", type=str, required=False, help="Password")
        parser_enum.add_argument("--query", type=str, required=False, help="Query")
        parser_enum.add_argument("--attribute", type=str, required=False, help="Attribute")
        parser_enum.add_argument("--predefined-query", type=str, required=False, choices=[e.value for e in PREDEFINED_QUERY], help="Predefined queries")

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), query=args.query, attribute=args.attribute, predefined_query=args.predefined_query, threads=args.threads, timeout=args.timeout, errors=args.errors, verbose=args.verbose, output=args.output, username=args.username, password=args.password)

    @error_handler([])
    def nv(self, hosts, **kwargs) -> None:
        super().nv(hosts, kwargs=kwargs)
        query = kwargs.get("query")
        username=kwargs.get("username")
        password=kwargs.get("password")
        predefined_query = kwargs.get("predefined_query", None)
        attribute = kwargs.get("attribute")

        if predefined_query:
            query, attribute = q[PREDEFINED_QUERY(predefined_query)]

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2(f"JMX Query", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose, query=query, attribute=attribute, username=username, password=password)


    @error_handler(["host"])
    def single(self, host, **kwargs):
        query=kwargs.get("query", "")
        attribute=kwargs.get("attribute", "")
        username=kwargs.get("username")
        password=kwargs.get("password")
        timeout=kwargs.get("timeout", 10)
        errors=kwargs.get("errors", False)
        verbose = kwargs.get("verbose", False)

        print(username, password)

        CONNECTION_URL = f"service:jmx:rmi:///jndi/rmi://{host}/jmxrmi"
        try:
            jmxConnection = jmxquery.JMXConnection(CONNECTION_URL, username, password) # type: ignore
            JMXQ = jmxquery.JMXQuery(query, attribute)
            q = jmxConnection.query([JMXQ])
            for a in q:
                self.print_output(a.value)

        except subprocess.CalledProcessError as e:
            self.print_output("Error", e.stderr)
        except Exception as e:
            self.print_output(f"Error {type(e)}")



class JMXServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("jmx")

        self.register_subservice(JMXQuerySubServiceClass())
