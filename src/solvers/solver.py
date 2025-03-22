import argparse
from src.solvers import grafana, openssl, php, python, tls, kibana, elastic, mongo, oracle, smb, ssh, snmp, tomcat, apache, nginx, vmware, openssh, smtp_relay, mssql, idrac, ipmi, terminal, cleartext, ibmwebsphere, obsolete_protocols, postgresql, nopasswddb, actionables, ftp, ntp, nfs, queuejumper, \
    openssl, webcgi_generic, hpilo, jenkins
from src.modules.nv_parse import GroupNessusScanOutput
import os

solver_dict = {
    0: actionables,
    1: tls,
    # 2: smtp_relay,
    3: ssh,
    4: ntp,
    5: smb,
    6: snmp,
    7: cleartext,
    8: terminal,
    9: nopasswddb,
    10: tomcat,
    11: apache,
    12: nginx,
    13: vmware,
    14: openssh,
    15: nfs,
    16: mssql,
    # 17: mDNS,
    18: obsolete_protocols,
    19: idrac,
    20: ipmi,
    21: php,
    22: grafana,
    23: python,
    24: kibana,
    25: elastic,
    26: mongo,
    27: oracle,
    28: queuejumper,
    29: ibmwebsphere,
    30: postgresql,
    31: ftp,
    32: openssl,
    # 33: webcgi_generic,
    34: hpilo, 
    35: jenkins,
}

def all_solver(args):
    for k,v in solver_dict.items():
        v.solve(args, is_all=True)
            
    
def create_config_file(args):
    s = ""
    for k,v in solver_dict.items():
        s += v.get_default_config()
    z = """
["1"]
allow_white_ciphers = true
"""
    
    with open(args.output, "w") as f:
        f.write(s)

json_output: list[GroupNessusScanOutput] = []

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nessus identified vulnerabilities solver.")
    
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v, -vv, -vvv, -vvvv, -vvvvvv)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    parser_config = subparsers.add_parser("create-config-file", help="Creates config file")
    parser_config.add_argument("-o", "--output", type=str, required=False, default="nv-config.toml", help="Output file name")
    parser_config.set_defaults(func=create_config_file)

    parser_all = subparsers.add_parser("all", help="Runs all solvers from json file")
    parser_all.add_argument("-f", "--file", type=str, default="output.ndjson", help="json file name (Default = output.ndjson)")
    parser_all.add_argument("-c", "--config", type=str, default="nv-config.toml", help="Config file (default: nv-config.toml).")
    parser_all.add_argument("--threads", type=int, default=10, help="Amounts of threads to use (Default = 10)")
    parser_all.add_argument("--timeout", type=int, default=5, help="Timeout (Default = 5)")
    parser_all.set_defaults(func=all_solver)
    parser_all.set_defaults(ignore_fail=True)

    for k,v in solver_dict.items():
        v.helper_parse(subparsers)


    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()