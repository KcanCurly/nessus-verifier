from src.utilities.utilities import Host, add_default_parser_arguments, add_default_solver_parser_arguments, find_scan, get_hosts_from_file2
import traceback

class BaseSolverClass():
    def __init__(self, name:str, id: int, args) -> None:
        self.name = name
        self.id = id
        self.args = args
        self.subhosts: dict[str, list[Host]] = {}
        self.hosts: list[Host] = []
        self.is_nv = True
        self._get_hosts(args)
        
    def get_default_config(self) -> str:
        return f"[{self.id}]"
        
    def helper_parse(self, subparser):
        parser_task1 = subparser.add_parser(str(self.id), help=self.name)
        add_default_solver_parser_arguments(parser_task1)
        add_default_parser_arguments(parser_task1, False)
        parser_task1.set_defaults(func=self.solve)
        
    def solve(self):
        print(f"Solve function for {self.id} has not been yet implemented.")
         
    def _get_subhosts(self, name):
        return self.subhosts.get(name, [])
        
    def _get_hosts(self, args):
        hosts: list[Host] = []
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
                
            for key, subhosts in scan.sub_hosts:
                self.subhosts[key] = []
                for h in subhosts:
                    ip, port = host.split(":")
                    self.subhosts[key].append(Host(ip, port))
                

        elif args.list_file:
            self.is_nv = False
            hosts = get_hosts_from_file2(args.list_file)
        return hosts
    
    def _print_exception(self, message, print_traceback = False):
        if self.args.errors:
            print(message)
            if print_traceback: 
                traceback.print_exc()