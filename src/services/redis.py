import redis
from src.utilities.utilities import Version_Vuln_Host_Data, get_default_context_execution2, error_handler
from src.services.consts import DEFAULT_ERRORS, DEFAULT_THREAD, DEFAULT_TIMEOUT, DEFAULT_VERBOSE
from src.services.serviceclass import BaseServiceClass
from src.services.servicesubclass import BaseSubServiceClass
"""
def list_redis_databases(host, port, password=None):
    try:
        # Connect to the Redis server
        client = redis.StrictRedis(host=host, port=port, password=password, decode_responses=True)

        # Check if the connection is successful
        if client.ping():
            print("Connected to Redis server")

        # List all databases by iterating through database indexes
        databases = []
        for db_index in range(16):  # Default Redis supports 16 databases (0-15)
            try:
                client.execute_command('SELECT', db_index)
                if client.dbsize() > 0:  # Check if the database has keys
                    databases.append(db_index)
            except redis.exceptions.ResponseError:
                break  # Stop if the database index is out of range

        print(f"Databases with keys: {databases}")
        return databases

    except redis.ConnectionError as e:
        print(f"Failed to connect to Redis server: {e}")
        return []
"""
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