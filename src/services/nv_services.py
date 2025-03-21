import argparse
from src.services import asterisk, dns, finger, ftp, ident, ldap, mongodb, ms_exchange, mssql, smb, ssh, snmp, nfs, rpc, smtp, snmp, tftp, time, mssql, idrac, zookeeper, postgresql, mysql

service_list = [
    dns,
    finger,
    ssh,
    ftp,
    smb,
    snmp,
    ident,
    ldap,
    mongodb,
    ms_exchange,
    nfs,
    rpc,
    smtp,
    snmp,
    mssql,
    tftp,
    idrac,
    time,
    zookeeper,
    postgresql,
    asterisk,
    mysql,
]


def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Service Pentesting.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    for v in service_list:
        try:
            v.helper_parse(subparsers)
        except:pass
    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
