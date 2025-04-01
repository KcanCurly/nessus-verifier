import argparse
from src.services import asterisk, chargen, daytime, discard, dns, echo, finger, ftp, ident, ldap, mongodb, ms_exchange, mssql, netstat, qotd, smb, ssh, snmp, nfs, rpc, smtp, snmp, systat, telnet, tftp, time, mssql, idrac, zookeeper, postgresql, mysql
from src.services.serviceclass import BaseServiceClass
from traceback import print_exc

service_dict: list[type[BaseServiceClass]] = [
    dns.DNSServiceClass,
    finger.FingerServiceClass,
    ssh.SSHServiceClass,
    ftp.FTPServiceClass,
    smb.SMBServiceClass,
    snmp.SNMPServiceClass,
    ident.IdentServiceClass,
    ldap.LDAPServiceClass,
    # mongodb.MongoDBServiceClass,
    # ms_exchange.MSExchangeServiceClass,
    nfs.NFSServiceClass,
    rpc.RPCServiceClass,
    # smtp.SMTPServiceClass,
    mssql.MSSQLServiceClass,
    tftp.TFTPServiceClass,
    idrac.IDRACServiceClass,
    time.TimeServiceClass,
    postgresql.PSQLServiceClass,
    asterisk.AsteriskServiceClass,
    mysql.MySQLServiceClass,
    telnet.TelnetServiceClass,
    systat.SystatServiceClass,
    netstat.NetstatServiceClass,
    qotd.QOTDServiceClass,
    echo.EchoServiceClass,
    discard.DiscardServiceClass,
    daytime.DaytimeServiceClass,
    chargen.ChargenServiceClass,
    zookeeper.ZookeeperServiceClass,
]


def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Service Pentesting.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    for v in service_dict:
        try:
            z = v() # type: ignore
            z.helper_parse(subparsers)
        except Exception as e:
            print(f"Error parsing {v.__name__}: {e}")
            print_exc()


    args = parser.parse_args()
    
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()
