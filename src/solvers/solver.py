import argparse
import json
from src.solvers import grafana, php, python, tls, kibana, elastic, mongo, oracle, smb, ssh, snmp, tomcat, apache, nginx, vmware, openssh, smtp_relay, mssql, idrac, ipmi
from src.modules.vuln_parse import GroupNessusScanOutput

solver_dict = {
    1: tls,
    # 2: smtp_relay,
    3: ssh,
    # 4: ntp
    5: smb,
    6: snmp,
    # 7: Cleartext Protocol Detected,
    # 8: Terminal Services Misconfigurations
    # 9: Usage of database without password
    10: tomcat,
    11: apache,
    12: nginx,
    13: vmware,
    14: openssh,
    # 15: NFS
    16: mssql,
    # 17: mDNS,
    # 18: Obsolete Protocols,
    19: idrac,
    20: ipmi,
    21: php,
    22: grafana,
    23: python,
}

def all_solver(args):
    ids = []
    with open(args.file, "r") as f:
        for line in f:
            ids.append(GroupNessusScanOutput.from_json(json.loads(line)).id)
            
    
    

json_output: list[GroupNessusScanOutput] = []

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nessus identified vulnerabilities solver.")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv, -vvv, -vvvv, -vvvvvv)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    
    # 0 - All
    parser_task1 = subparsers.add_parser("all", help="Runs all solvers from json file")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="json file name")
    
    parser_task1.set_defaults(func=all_solver)

    for k,v in solver_dict.items():
        v.helper_parse(subparsers)

    
    # 24 - Kibana
    parser_task1 = subparsers.add_parser("24", help="Kibana")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=kibana.entry_solver)
    
    # 25 - Elastic
    parser_task1 = subparsers.add_parser("25", help="Elastic")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=elastic.entry_solver)
    
    # 26 - MongoDB
    parser_task1 = subparsers.add_parser("26", help="MongoDB")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=mongo.entry_solver)
    
    # 27 - Oracle Database 
    parser_task1 = subparsers.add_parser("27", help="Oracle Database")
    parser_task1.add_argument("-f", "--file", type=str, required=True, help="Host file name")
    parser_task1.set_defaults(func=oracle.entry_solver)
    
    
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()