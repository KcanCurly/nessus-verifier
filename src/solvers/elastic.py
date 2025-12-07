from src.utilities.utilities import Version_Vuln_Host_Data, error_handler, get_url_response, get_default_context_execution, get_cves, get_poc_cve_github_link
from packaging.version import parse
from src.solvers.solverclass import BaseSolverClass

class ElasticsearchSolverClass(BaseSolverClass):
    def __init__(self) -> None:
        super().__init__("Elasticsearch", 25)
        self.output_filename_for_all = "elastic.txt"
        self.output_png_for_action = "elastic.png"
        self.action_title = "Elastic"
        self.eol_product_name = "elasticsearch"

    def solve(self, args):
        self.process_args(args)

        if not self.hosts:
            return

        self.solve_version(self.hosts, args.threads, args.timeout, args.errors, args.verbose)


    @error_handler(["host"])
    def solve_version_single(self, host, timeout, errors, verbose):
        resp = get_url_response(host, timeout=timeout)
        if not resp:
            return
        version = resp.json()['version']['number']
        return Version_Vuln_Host_Data(host, version)

    
    @error_handler([])
    def solve_version(self, hosts, threads, timeout, errors, verbose):
        versions = {}
        results: list[Version_Vuln_Host_Data] = get_default_context_execution("Elastic Version", threads, hosts, (self.solve_version_single, timeout, errors, verbose))
        
        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        all_cves = set()

        if versions:       
            versions = dict(
                sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
            )
            self.print_output("Elastic versions detected:")
            for key, value in versions.items():
                cves = []
                if self.print_cve:
                    cves = get_cves(f"cpe:2.3:a:elastic:elasticsearch:{key}")
                if cves:
                    all_cves.update(cves)
                    self.print_output(f"Elasticsearch {key} ({", ".join(cves)}):")
                else: self.print_output(f"Elasticsearch {key}:")
                for v in value:
                    self.print_output(f"    {v}")
            self.create_windowcatcher_action()
            self.print_latest_versions()

            for cve in all_cves:
                links = get_poc_cve_github_link(cve)
                if links:
                    self.print_output(f"{cve}:")
                    for link in links:
                        self.print_output(link)
    

    