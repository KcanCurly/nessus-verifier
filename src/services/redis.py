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
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Redis Post", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        



    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)
        ip = host.ip
        port = host.port

        client = redis.Redis(host=host.ip, port=int(host.port), password=None, decode_responses=True)

        max_dbs = 16  # Default max DBs (configurable in Redis)
        databases = []
        
        for db in range(max_dbs):
            try:
                client.execute_command(f"SELECT {db}")  # Switch to database
                keys = client.keys("*")  # Get all keys in the DB
                for key in keys[:10]: # type: ignore
                    print(f"  - {key}")
            except redis.exceptions.ResponseError as z:
                break  # If the database does not exist, break the loop


class RedisVersionSubServiceClass(BaseSubServiceClass):
    def __init__(self) -> None:
        super().__init__("version", "Checks Redis version")

    @error_handler([])
    def nv(self, hosts, **kwargs):
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[Version_Vuln_Host_Data] = get_default_context_execution2("Redis Version", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)
        versions = {}

        for r in results:
            if r.version not in versions:
                versions[r.version] = set()
            versions[r.version].add(r.host)
        if versions:
            versions = dict(sorted(versions.items(), reverse=True))
            print("Detected Redis Versions:")
            for r, values in versions.items():
                cves = get_cves(f"cpe:2.3:a:redis:redis:{r}")
                if cves:
                    print(f"{r} ({", ".join(cves)}):")
                else:
                    print(f"{r}:")
                for v in values:
                    print(f"    {v}")

    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

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
        threads = kwargs.get("threads", DEFAULT_THREAD)
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        results: list[str] = get_default_context_execution2("Redis Unauth", threads, hosts, self.single, timeout=timeout, errors=errors, verbose=verbose)

        if results:
            print(f"Unauthenticated Redis instances found:")
            for r in results:
                print(r)


    @error_handler(["host"])
    def single(self, host, **kwargs):
        timeout = kwargs.get("timeout", DEFAULT_TIMEOUT)
        errors = kwargs.get("errors", DEFAULT_ERRORS)
        verbose = kwargs.get("errors", DEFAULT_VERBOSE)

        client = redis.StrictRedis(host=host.ip, port=int(host.port), password=None, decode_responses=True)

        # Check if the connection is successful
        if client.info():
            return host

class RedisServiceClass(BaseServiceClass):
    def __init__(self) -> None:
        super().__init__("redis")
        self.register_subservice(RedisUnauthSubServiceClass())
        self.register_subservice(RedisVersionSubServiceClass())
        self.register_subservice(RedisPostSubServiceClass())