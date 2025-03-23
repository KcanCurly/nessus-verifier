# Nessus Verifier

This is a project for penetration testing for nessus service outputs.

## Installation

To install:

```
cd ~
sudo apt install -y sslscan sshpass ssh-audit dnsutils dnsrecon nmap metasploit-framework ident-user-enum smbclient samba samba-common-bin tnscmd10g libnfs-utils cpanminus git pipx libpq5 libpq-dev sippts
pipx install git+https://github.com/KcanCurly/nessus-verifier
sudo cpanm --notest Encoding::BER
git clone https://github.com/CiscoCXSecurity/rdp-sec-check
```

## Usage

```
nv-parse -f file.nessus
nv-solver all -f output.ndjson
```

## Implemented Applications
* QOTD
  * Checks usage
  * Bannger grab
* Netstat
  * Checks usage
  * Bannger grab
* Systat
  * Checks usage
  * Bannger grab
* Telnet
  * Checks usage and product version
  * Bannger grab
* FTP
  * Check Anonymous access
  * Check common/default credentials
  * Check TSL/SSL versions and ciphers and bits
  * Check if anonymous and local users are forced to use SSL
* SSH
  * Check common/default credentials
  * Check hostkey/kex/mac/ciphers and protocol version
  * Check software version and (FUTURE) print CVEs related to those version
* SMTP
  * Checks if TLS is enforced
  * If TLS is used check TSL/SSL versions and ciphers and bits
  * Checks if it is open relay (Please check configuration file to specify e-mails)
  * Checks if user enum is possible with VRFY,EXPN,RCPT
* Time
  * Checks the usage and prints out the server time
* TACACS (FUTURE)
* DNS
  * Check if recursion is enabled
  * Check if zone transfer(AXFR) is possible
  * Check if we can add a record to the dns server
  * Check if server can resolve malicious domain
  * Check if server supports DNS over TLS, if so do usual TLS enumeration
  * Check if server is vulnerable to cache posioning
  * Check if ANY query reveals more than just NS records
* TFTP
  * File enumeration with msf
* Finger
  * User enumeration with msf
* Ident
  * Process/User enumeration
* NTP (FUTURE)
* RPC
  * Check null access on pipes: LSARPC, SAMR, SPOOLSS, SRVSVC, DFS, WKSSVC, NTSVCS, DRSUAPI, EVENTLOG, WINREG, FSRVP
* IMAP
  * Check if TLS is used or forced
* SNMP
  * Bruteforce credentials
* IRC (FUTURE)
* LDAP
  * Check anonymous access
* SMB
  * Check null and guest access print shares if so
  * Check smb signing requirement
  * Check smb version
* Rlogin
  * Simply checks usage and prints out the hosts

## Implemented Applications

* Microsoft Exchange
  * Check computer name with autodiscover and exchange version with Exchange.asmx

## Implemented Vulnerability Grouping and Solvers

* TLS Misconfigurations
* SMTP - Open Relay Test (TODO)
* SSH Service Misconfigurations
* NTP Mode 6
* SMB Service Misconfigurations
* SNMP Service Misconfigurations
* Cleartext Protocol Detected
* Terminal Services Misconfigurations
* Usage of database without password
* Apache Tomcat
* Apache Server
* Nginx
* VMWare Products
* OpenSSH
* NFS
* MSSQL
* mDNS (TODO)
* Obsolete Protocols (TODO)
* iDRAC
* IPMI
* PHP
* Grafana
* Python Unsupported Version
* Kibana
* Elasticsearch
* MongoDB
* Oracle Database
* QueueJumper
* IBM WebSphere
* PostgreSQL
* FTP
* OpenSSL
* Web/CGI Generic
* HP iLO
* Jenkins