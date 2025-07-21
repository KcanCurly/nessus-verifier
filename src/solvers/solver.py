import argparse
import shutil
from src.solvers import grafana, mdns, openssl, php, python, tls, kibana, elastic, mongo, oracle, smb, ssh, snmp, tomcat, apache, nginx, vmware, openssh, smtp_relay, mssql, idrac, ipmi, terminal, cleartext, ibmwebsphere, obsolete_protocols, postgresql, nopasswddb, actionables, ftp, ntp, nfs, queuejumper, \
    openssl, webcgi_generic, hpilo, jenkins
from src.modules.nv_parse import GroupNessusScanOutput
from src.solvers.solverclass import BaseSolverClass
from src.utilities.utilities import nvd_api_key
import os

solver_dict: dict[int, type[BaseSolverClass]] = {
    0: actionables.ActionablesSolverClass,
    1: tls.TLSSolverClass,
    # 2: smtp_relay,
    3: ssh.SSHAuditSolverClass,
    4: ntp.NTPSolverClass,
    5: smb.SMBSolverClass,
    6: snmp.SNMPSolverClass,
    7: cleartext.CleartextSolverClass,
    8: terminal.TerminalSolverClass,
    9: nopasswddb.NoPasswordDBSolverClass,
    10: tomcat.TomcatSolverClass,
    11: apache.ApacheSolverClass,
    12: nginx.NginxSolverClass,
    13: vmware.VmwareSolverClass,
    14: openssh.OpenSSHSolverClass,
    15: nfs.NFSSolverClass,
    16: mssql.MSSQLSolverClass,
    17: mdns.MDNSSolverClass,
    18: obsolete_protocols.ObsoleteProtocolSolverClass,
    19: idrac.IDRACSolverClass,
    20: ipmi.IPMISolverClass,
    21: php.PHPSolverClass,
    22: grafana.GrafanaSolverClass,
    23: python.PythonSolverClass,
    24: kibana.KibanaSolverClass,
    25: elastic.ElasticsearchSolverClass,
    26: mongo.MongoSolverClass,
    27: oracle.OracleSolverClass,
    28: queuejumper.QueueJumperSolverClass,
    29: ibmwebsphere.IBMWebSphereSolverClass,
    30: postgresql.PSQLSolverClass,
    31: ftp.FTPSolverClass,
    32: openssl.OpenSSLSolverClass,
    # 33: webcgi_generic,
    34: hpilo.HPiLOSolverClass, 
    35: jenkins.JenkinsSolverClass,
}

def all_solver(args):
    if args.output_directory:
        if os.path.exists(args.output_directory):
            shutil.rmtree(args.output_directory)
        os.makedirs(args.output_directory)

    if args.create_actions:
        if os.path.exists(args.create_actions):
            os.remove(args.create_actions)

    for k,v in solver_dict.items():
        zz = v() # type: ignore
        zz.solve(args)

            
def create_config_file(args):
    s = ""
    for k,v in solver_dict.items():
        zz = v() # type: ignore
        s += zz.get_default_config()
            
    with open(args.output, "w") as f:
        f.write(s)

json_output: list[GroupNessusScanOutput] = []

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Nessus identified vulnerabilities solver.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    parser_config = subparsers.add_parser("ccf", help="Create config file")
    parser_config.add_argument("-o", "--output", type=str, required=False, default="nv-config.toml", help="Output file name")
    parser_config.set_defaults(func=create_config_file)

    parser_all = subparsers.add_parser("all", help="Runs all solvers from json file")
    parser_all.add_argument("-f", "--file", type=str, default="output.ndjson", help="json file name (Default = output.ndjson)")
    parser_all.add_argument("-c", "--config", type=str, default="nv-config.toml", help="Config file (default: nv-config.toml).")
    parser_all.add_argument("-a", "--create-actions", type=str, default=None, help="Creates action toml file for windowcatcher with given name.")
    parser_all.add_argument("-od", "--output-directory", type=str, required=False, help="Output directory.")
    parser_all.add_argument("-s", "--space", type=str, default=0, help="Amount of spaces to prepend when printing affected hosts. (Default = 0)")    
    parser_all.add_argument("--nvd-api-key", type=str, help="NVD API Key for getting cves.")
    parser_all.add_argument("-th", "--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    parser_all.add_argument("-ti", "--timeout", type=int, default=5, help="Amount of timeout (Default = 5).")
    parser_all.add_argument("-e", "--errors", type=int, choices=[1, 2], default = 0, help="1 - Print Errors\n2 - Print errors and prints stacktrace")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Print Verbose")
    parser_all.set_defaults(func=all_solver)
    parser_all.set_defaults(is_all=True)

    for _,v in solver_dict.items():
        zz = v() # type: ignore
        zz.helper_parse(subparsers)


    args = parser.parse_args()
    
    if hasattr(args, "func"):
        if hasattr(args, "nvd_api_key") and args.nvd_api_key is not None:
            global nvd_api_key
            nvd_api_key = args.nvd_api_key
        args.func(args)
    else:
        parser.print_help()