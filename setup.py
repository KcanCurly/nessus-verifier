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
        "requests",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    entry_points={
        "console_scripts": [
            "nv-parse=src.main:main",
            "nv-ssh=src.modules.ssh:main",
            "nv-ftp=src.modules.ftp:main",
            "nv-chargen=src.modules.chargen:main",
            "nv-qotd=src.modules.qotd:main",
            "nv-daytime=src.modules.daytime:main",
            "nv-systat=src.modules.systat:main",
            "nv-discard=src.modules.discard:main",
            "nv-echo=src.modules.echo:main",
            "nv-netstat=src.modules.netstat:main",
            "nv-telnet=src.modules.telnet:main",
            "nv-smtp=src.modules.smtp:main",
            "nv-ms-exchange=src.modules.ms_exchange:main",
        ],
    },
)
