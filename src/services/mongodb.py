import pprint
from src.utilities.utilities import Version_Vuln_Data, get_cves, get_hosts_from_file, add_default_parser_arguments, get_default_context_execution
from pymongo import MongoClient
import pymongo
from packaging.version import parse

def post_nv(hosts, threads, timeout, errors, verbose):
    for host in hosts:
        try:
            ip, port = host.split(":")
            client = MongoClient(ip, int(port))
            dbs = client.list_databases()
            for db in dbs:
                print(f"Database: {db["name"]}")
                print("=====================")
                d = client[db["name"]]
                cols = d.list_collections()
                for c in cols:
                    print(c["name"])
                    print("---------------------")
                    doc = d[c["name"]]
                    for post in doc.find(filter="", limit=5):
                        pprint.pprint(post)
                    print()
                        
                print()

        except:pass
        
def post_console(args):
    post_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)


def unauth_nv(hosts, threads, timeout, errors, verbose):
    vuln = []
    
    for host in hosts:
        try:
            ip, port = host.split(":")
            with pymongo.timeout(timeout):
                client = MongoClient(ip, int(port))
                dbs = client.list_databases()
                vuln.append(host)

        except:pass
    
    if len(vuln) > 0:
        print("MongoDB Unauthenticated Access:")
        for v in vuln:
            print(f"    {v}")

def unauth_console(args):
    unauth_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def version_single(host, timeout, errors, verbose):
    try:
        ip, port = host.split(":")
        with pymongo.timeout(timeout):
            client = MongoClient(ip, int(port))
            version = client.server_info()['version']
            return Version_Vuln_Data(host, version)

    except Exception as e: 
        if errors: print(f"Error for {host}: {e}")

def version_nv(hosts, threads, timeout, errors, verbose):
    versions = {}
    results: list[Version_Vuln_Data] = get_default_context_execution("MongoDB Version", threads, hosts, (version_single, timeout, errors, verbose))
    
    
    for r in results:
        if r.version not in versions:
            versions[r.version] = set()
        versions[r.version].add(r.host)

    if len(versions) > 0:      
        versions = dict(
            sorted(versions.items(), key=lambda x: parse(x[0]), reverse=True)
        ) 
        print("MongoDB versions detected:")
        for key, value in versions.items():
            cves = get_cves(f"cpe:2.3:a:mongodb:mongodb:{key}")
            if cves: print(f"MongoDB {key} ({", ".join(cves)}):")
            else: print(f"MongoDB {key}:")  
            for v in value:
                print(f"    {v}")

def version_console(args):
    version_nv(get_hosts_from_file(args.target), args.threads, args.timeout, args.errors, args.verbose)

def helper_parse(commandparser):    
    parser_task1 = commandparser.add_parser("mongodb")
    subparsers = parser_task1.add_subparsers(dest="command")
    
    parser_version = subparsers.add_parser("version", help="Checks version")
    add_default_parser_arguments(parser_version)
    parser_version.set_defaults(func=version_console)
    
    parser_unauth = subparsers.add_parser("unauth", help="Checks if unauthenticated access is allowed")
    add_default_parser_arguments(parser_unauth)
    parser_unauth.set_defaults(func=unauth_console)
    
    parser_post = subparsers.add_parser("post", help="Post Exploit")
    parser_post.add_argument("target", type=str, help="File name or targets seperated by space")
    parser_post.add_argument("username", type=str, required=True, help="Username")
    parser_post.add_argument("password", type=str, required=True, help="Password")
    add_default_parser_arguments(parser_post, False)
    parser_post.set_defaults(func=post_console)

