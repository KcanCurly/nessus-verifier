import argparse
import pymongo
from src.utilities import get_hosts_from_file
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure

def entry_solver(args):
    solve(args.file)

def entry_cmd():
    parser = argparse.ArgumentParser(description="MongoDB")
    parser.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    
    args = parser.parse_args()
    
    entry_solver(args)

def solve(hosts, white_results_are_good = False):
    versions: dict[str, str] = {}
    hosts = get_hosts_from_file(hosts)
    for host in hosts:
        try:
            ip = host.split(":")[0]
            port = host.split(":")[1]
            client = MongoClient(ip, int(port))
            version = client.server_info()['version']
            if version not in versions:
                versions[version] = set()
            versions[version].add(host)  
        except Exception as e: print(f"Error for {host}:", e)
                    
      
    if len(versions) > 0:       
        print("MongoDB versions detected:")                
        for key, value in versions.items():
            print(f"{key}:")
            for v in value:
                print(f"\t{v}")
    
    
            
if __name__ == "__main__":
    entry_cmd()