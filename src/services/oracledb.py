import oracledb
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
from src.utilities.utilities import error_handler, get_hosts_from_file2

class OracleDBMiniShellSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("minishell", "OracleDB Mini Shell")

    def helper_parse(self, subparsers):
        parser = subparsers.add_parser(self.command_name, help = self.help_description)
        parser.add_argument("target", type=str, help="IP:Port of OracleDB server")
        parser.add_argument("username", type=str)
        parser.add_argument("password", type=str)
        parser.add_argument("service", type=str)

    def console(self, args):
        self.nv(get_hosts_from_file2(args.target), username=args.username, password=args.password, service=args.service)

    @error_handler([])
    def nv(self, hosts, **kwargs):
        username = kwargs.get("username")
        password = kwargs.get("password")
        service = kwargs.get("service")
        cs = f"{hosts}/{service}"

        with oracledb.connect(user=username, password=password, dsn=cs) as connection:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM user_tab_privs "
                for r in cursor.execute(sql):
                    print(r)

class OracleDBServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("oracledb")
