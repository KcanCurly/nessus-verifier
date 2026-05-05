from src.utilities.utilities import Host, add_default_solver_parser_arguments, find_scan, get_hosts_from_file2, get_latest_version
import traceback
import os
import i18n

class BaseSolverClass():
    def __init__(self, name:str, id: int) -> None:
        self.name = name
        self.id = id
        self.subhosts: dict[str, list[Host]] = {}
        self.hosts: list[Host] = []
        self.is_nv = True
        self.spaces_before_hosts = 0
        self.output = ""
        self.eol_product_name = ""
        self.print_cve = True
        self.print_latest_version = True
        self.print_poc = True
        self.output_filename_for_all = ""

    def get_latest_version(self, print_title = True):
        if self.eol_product_name:
            return get_latest_version(self.eol_product_name)



    def process_args(self, args):
        self.args = args
        current_script_path = os.path.abspath(__file__)
        dir_up = os.path.abspath(os.path.join(current_script_path, "../../"))
        locales_dir = os.path.join(dir_up, "locales")
        i18n.load_path.append(locales_dir) # type: ignore
        i18n.set('locale', args.language) # type: ignore
        if hasattr(args, "is_all") and args.is_all: 
            self.process_config(args.config)
            if hasattr(args, "output_directory") and args.output_directory:
                self.output = os.path.join(args.output_directory, self.output_filename_for_all)
        if hasattr(args, "no_print_cve") and args.no_print_cve:
            self.print_cve = False
        if hasattr(args, "no_print_latest_version") and args.no_print_latest_version:
            self.print_latest_version = False
        if hasattr(args, "no_print_poc") and args.no_print_poc:
            self.print_poc = False
        self._get_hosts(args)

    def print_latest_versions(self):
        latest_versions = self.get_latest_version()
        if latest_versions:
            self.print_output(f"Latest version for {self.eol_product_name}")
            self.print_output(f"{self.eol_product_name}:" + ", ".join(latest_versions))

    def print_output(self, message):
        print(message)
        if self.output:
            with open(self.output, "a") as f:
                print(message, file=f)

    def process_config(self, config: str) -> None:
        pass
        
    def get_default_config(self) -> str:
        return f"[{self.id}]\n"
        
    def helper_parse(self, subparser):
        parser_task1 = subparser.add_parser(str(self.id), help=self.name)
        add_default_solver_parser_arguments(parser_task1)
        parser_task1.set_defaults(func=self.solve)
        
    def solve(self, args):
        return

    def _get_subhosts(self, name):
        return self.subhosts.get(name, [])
        
    def _get_hosts(self, args):
        if args.file:
            scan = find_scan(args.file, self.id)
            if not scan: 
                if hasattr(args, "is_all") and args.is_all:
                    return
                print("File or id in file not found")
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

