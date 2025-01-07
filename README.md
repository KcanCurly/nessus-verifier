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
nv-ssh ports/ssh
nv-ftp ports/ftp
```

## Implemented services

* Echo
* Discard
* Systat
* Daytime
* QOTD
* CHARGEN
* FTP
  * Check Anonymous access
  * Check common/default credentials
  * Check TSL/SSL versions and ciphers
  * (FUTURE) Check if anonymous and local users are forced to use SSL
* SSH
  * Check common/default credentials
  * Check hostkey/kex/mac/ciphers and protocol version
  * Check software version and (FUTURE) print CVEs related to those version


