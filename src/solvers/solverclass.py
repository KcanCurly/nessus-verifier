from src.utilities.utilities import Host, add_default_parser_arguments, add_default_solver_parser_arguments, find_scan, get_hosts_from_file2
import traceback

class BaseSolverClass():
    def __init__(self, name:str, id: int) -> None:
        self.name = name
        self.id = id
        self.subhosts: dict[str, list[Host]] = {}
        self.hosts: list[Host] = []
        self.is_nv = True
        self.spaces_before_hosts = 0

    def process_config(self, config: str) -> None:
        pass
        
    def get_default_config(self) -> str:
        return f"[{self.id}]\n"
        
    def helper_parse(self, subparser):
        parser_task1 = subparser.add_parser(str(self.id), help=self.name)
        add_default_solver_parser_arguments(parser_task1)
        add_default_parser_arguments(parser_task1, False)
        parser_task1.set_defaults(func=self.solve)
        
    def solve(self, args):
        self.args = args
        if hasattr(args, "is_all") and args.is_all: self.process_config(args.config)
        self._get_hosts(args)
         
    def _get_subhosts(self, name):
        return self.subhosts.get(name, [])
        
    def _get_hosts(self, args):
        if args.file:
            scan = find_scan(args.file, self.id)
            if not scan: 
                if args.is_all: 
                    return
                print("File not found")
                return
            for host in scan.hosts:
                ip, port = host.split(":")
                self.hosts.append(Host(ip, port))
                
            for key, subhosts in scan.sub_hosts.items():
                self.subhosts[key] = []
                for h in subhosts:
                    ip, port = h.split(":")
                    self.subhosts[key].append(Host(ip, port))
                

        elif args.list_file:
            self.is_nv = False
            self.hosts = get_hosts_from_file2(args.list_file)

    def _print_exception(self, message, print_traceback = False):
        if self.args.errors:
            print(message)
            if print_traceback: 
                traceback.print_exc()