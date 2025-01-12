# Nessus Verifier

This is a project for penetration testing for nessus service outputs.

## Installation

To install:

```
pipx install git+https://github.com/KcanCurly/nessus-verifier
pipx install git+https://github.com/KcanCurly/ssh-whirl
sudo apt install -y sslscan sshpass ssh-audit
```

## Usage

```
nv-parse file.nessus
```

This will create ports directory with service directories inside, after that you can use smaller modules to target the service directory

```
nv-ssh ports/ssh [directory path] [filename of the hosts]
nv-ftp ports/ftp [directory path] [filename of the hosts]
```

## Implemented Applications

* Echo
  * Simply checks usage and prints out the hosts
* Discard
  * Simply checks usage and prints out the hosts
* Systat
  * Simply checks usage and prints out the hosts
* Daytime
  * Simply checks usage and prints out the hosts
* QOTD
  * Simply checks usage and prints out the hosts
* CHARGEN
  * Simply checks usage and prints out the hosts
* FTP
  * Check Anonymous access
  * Check common/default credentials
  * Check TSL/SSL versions and ciphers and bits
  * Check if anonymous and local users are forced to use SSL
* SSH
  * Check common/default credentials
  * Check hostkey/kex/mac/ciphers and protocol version
  * Check software version and (FUTURE) print CVEs related to those version
* Telnet
  * Simply checks usage and prints out the hosts
* SMTP
  * Checks if TLS is enforced
  * If TLS is used check TSL/SSL versions and ciphers and bits
  * Checks if it is open relay (Please check configuration file to specify e-mails)
  * Checks if user enum is possible with VRFY,EXPN,RCPT


## Implemented Applications

* Microsoft Exchange
  * Check computer name with autodiscover and exchange version with Exchange.asmx