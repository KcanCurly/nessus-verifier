from setuptools import setup, find_packages

setup(
    name="nessus_verifier",
    version="0.0.1",
    description="Pentests services from nessus file",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="kcancurly",
    url="https://github.com/kcancurly/nessus-verifier",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "argcomplete",
        "requests",
        "dnspython",
        "ntplib",
        "impacket",
        "pyaml",
        "pysmb",
        "pymongo",
        "python-nmap",
        "rich",
        "psycopg",
        "paramiko",
        "toml",
        "stomp.py",
        "pymssql",
        "asyncssh[bcrypt]",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    entry_points={
        "console_scripts": [
            "nv-parse=src.modules.nv_parse:main",
            "nv-solver=src.solvers.solver:main",
            "nv-nmap=src.modules.nv_nmap:main",
            "nv-service=src.services.nv_services:main",
            "nv-ssh=src.services.ssh:main",
            "nv-systat=src.services.systat:main",
            "nv-netstat=src.services.netstat:main",
            "nv-smtp=src.services.smtp:main",
            "nv-tftp=src.services.tftp:main",
            "nv-ntp=src.services.ntp:main",
            "nv-rpc=src.services.rpc:main",
            "nv-snmp=src.services.snmp:main",
            "nv-smb=src.services.smb:main",
            "nv-rlogin=src.services.rlogin:main",
            "nv-psql=src.services.postgresql:main",
            "nv-activemq=src.services.activemq:main",
            "nv-zookeeper=src.services.zookeeper:main",
            "nv-mssql=src.services.mssql:main",
            "nv-snaffler-ssh=src.snaffler.ssh.main:main",
            "nv-snaffler-smb=src.snaffler.smb.main:main",
        ],
    },
)
