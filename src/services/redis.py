import i18n
import redis
import redis.exceptions
from src.utilities.utilities import Version_Vuln_Host_Data, get_cves, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass

class RedisPostSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("post", "Post-exploit stuff")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Redis Post", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

    @error_handler(["host"])
    def single(self, host, **kwargs):
        ip = host.ip
        port = host.port

        client = redis.Redis(host=ip, port=int(port), password=None, decode_responses=True)

        max_dbs = 16  # Default max DBs (configurable in Redis)
        
        for db in range(max_dbs):
            try:
                client.execute_command(f"SELECT {db}")  # Switch to database
                keys = client.keys("*")  # Get all keys in the DB
                for key in keys[:10]: # type: ignore
                    self.print_output(f"  - {key}")
            except redis.exceptions.ResponseError as z:
                break  # If the database does not exist, break the loop


class RedisVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks Redis version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Redis Version", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)
        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            self.print_output(i18n.t('main.version_title', name="Redis"))
            for r, values in versions.items():
                cves = get_cves(f"cpe:2.3:a:redis:redis:{r}")
                if cves:
                    self.print_output(f"{r} ({", ".join(cves)}):")
                else:
                    self.print_output(f"{r}:")
                for v in values:
                    self.print_output(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        client = redis.StrictRedis(host=host.ip, port=int(host.port), password=None, decode_responses=True)

        # Check if the connection is successful
        inf = client.info()  # type: ignore
        redis_version = inf.get("redis_version", "Unknown")  # type: ignore
        return Version_Vuln_Host_Data(host, redis_version)

class RedisUnauthSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("unauth", "Checks unauthenticated Redis instances")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        super().nv(hosts, kwargs=kwargs)

        results: list[str] = get_default_context_execution2("Redis Unauth", self.threads, hosts, self.single, timeout=self.timeout, errors=self.errors, verbose=self.verbose)

        if results:
            self.print_output(i18n.t('main.unauth_database_access', name="Redis"))
            for r in results:
                self.print_output(r)
            self.print_output("redis-cli -h x.x.x.x -p 6379 info")
            


    @error_handler(["host"])
    def single(self, host, **kwargs):
        client = redis.StrictRedis(host=host.ip, port=int(host.port), password=None, decode_responses=True)

        # Check if the connection is successful
        if client.info():
            return host

class RedisServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("redis")
        self.register_subservice(RedisUnauthSubServiceClass())
        self.register_subservice(RedisVersionSubServiceClass())
        # self.register_subservice(RedisPostSubServiceClass())