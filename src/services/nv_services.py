import argparse
import os
import subprocess
from src.services import activemq, ajp13, amqp, asterisk, chargen, daytime, discard, dns, echo, finger, ftp, http, ident, ldap, mdns, mongodb, ms_exchange, mssql, netstat, qotd, smb, ssh, snmp, nfs, rpc, smtp, snmp, systat, telnet, tftp, time, mssql, idrac, zookeeper, postgresql, mysql, redis
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
    mongodb.MongoDBServiceClass,
    # ms_exchange.MSExchangeServiceClass,
    nfs.NFSServiceClass,
    rpc.RPCServiceClass,
    smtp.SMTPServiceClass,
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
    amqp.AMQPServiceClass,
    redis.RedisServiceClass,
    activemq.AMQPServiceClass,
    ajp13.AJP13ServiceClass,
    mdns.MDNSServiceClass,
    http.HTTPServiceClass,
]


def all_solver(args):
    h = "hosts.txt"
    l = "cifs"
    if os.path.exists(args.directory):
        if os.path.exists(os.path.join(args.directory, "cifs", h)):
            command = ["nv-service", "smb", "smbv1", os.path.join(args.directory, "cifs", h)]
            subprocess.run(command)
            command = ["nv-service", "smb", "nullguest", os.path.join(args.directory, "cifs", h)]
            subprocess.run(command)
            command = ["nv-service", "smb", "os-version", os.path.join(args.directory, "cifs", h)]
            subprocess.run(command)
            command = ["nv-service", "smb", "null-session", os.path.join(args.directory, "cifs", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "ftp", h)):
            command = ["nv-service", "ftp", "anonymous", os.path.join(args.directory, "ftp", h)]
            subprocess.run(command)
            command = ["nv-service", "ftp", "version", os.path.join(args.directory, "ftp", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "dns", h)):
            command = ["nv-service", "dns", "version", os.path.join(args.directory, "dns", h)]
            subprocess.run(command)
            command = ["nv-service", "dns", "axfr", os.path.join(args.directory, "dns", h)]
            subprocess.run(command)
            command = ["nv-service", "dns", "any", os.path.join(args.directory, "dns", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "mdns", h)):
            command = ["nv-service", "mdns", "discovery", os.path.join(args.directory, "mdns", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "snmp", h)):
            command = ["nv-service", "snmp", "default", os.path.join(args.directory, "snmp", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "ldap", h)):
            command = ["nv-service", "ldap", "anonymous", os.path.join(args.directory, "ldap", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "mongodb", h)):
            command = ["nv-service", "mongodb", "unauth", os.path.join(args.directory, "mongodb", h)]
            subprocess.run(command)
            command = ["nv-service", "mongodb", "version", os.path.join(args.directory, "mongodb", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "nfs", h)):
            command = ["nv-service", "nfs", "list", os.path.join(args.directory, "nfs", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "epmap", h)):
            command = ["nv-service", "rpc", "anonymous", os.path.join(args.directory, "epmap", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "mssql", h)):
            command = ["nv-service", "mssql", "version", os.path.join(args.directory, "mssql", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "tftp", h)):
            command = ["nv-service", "tftp", "brute", os.path.join(args.directory, "tftp", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "mysql", h)):
            command = ["nv-service", "mysql", "version", os.path.join(args.directory, "mysql", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "postgresql", h)):
            command = ["nv-service", "psql", "default", os.path.join(args.directory, "postgresql", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "telnet", h)):
            command = ["nv-service", "telnet", "usage", os.path.join(args.directory, "telnet", h)]
            subprocess.run(command)
            command = ["nv-service", "telnet", "banner", os.path.join(args.directory, "telnet", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "zookeeper", h)):
            command = ["nv-service", "zookeeper", "zookeeper", os.path.join(args.directory, "zookeeper", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "redis", h)):
            command = ["nv-service", "redis", "unauth", os.path.join(args.directory, "redis", h)]
            subprocess.run(command)
            command = ["nv-service", "redis", "version", os.path.join(args.directory, "redis", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "amqp", h)):
            command = ["nv-service", "amqp", "version", os.path.join(args.directory, "amqp", h)]
            subprocess.run(command)
        if os.path.exists(os.path.join(args.directory, "activemq", h)):
            command = ["nv-service", "activemq", "version", os.path.join(args.directory, "activemq", h)]
            subprocess.run(command)

def main():
    # Create the main parser
    parser = argparse.ArgumentParser(description="Service Pentesting.")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    parser_all = subparsers.add_parser("all", help="Runs all solvers from json file")
    parser_all.add_argument("-d", "--directory", type=str, default="nv-services", help="json file name (Default = output.ndjson)")
    # parser_all.add_argument("-c", "--config", type=str, default="nv-config.toml", help="Config file (default: nv-config.toml).")
    # parser_all.add_argument("-a", "--create-actions", type=str, default=None, help="Creates action toml file for windowcatcher with given name.")
    # parser_all.add_argument("-od", "--output-directory", type=str, required=False, help="Output directory.")
    # parser_all.add_argument("-s", "--space", type=str, default=0, help="Amount of spaces to prepend when printing affected hosts. (Default = 0)")    
    parser_all.add_argument("--nvd-api-key", type=str, help="NVD API Key for getting cves.")
    parser_all.add_argument("-th", "--threads", type=int, default=10, help="Amount of threads (Default = 10).")
    parser_all.add_argument("-ti", "--timeout", type=int, default=5, help="Amount of timeout (Default = 5).")
    parser_all.add_argument("-e", "--errors", type=int, choices=[1, 2], default = 0, help="1 - Print Errors\n2 - Print errors and prints stacktrace")
    parser_all.add_argument("-v", "--verbose", action="store_true", help="Print Verbose")
    parser_all.set_defaults(func=all_solver)

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
