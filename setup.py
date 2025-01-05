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
    install_requires=[
        "tqdm",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    entry_points={
        "console_scripts": [
            "nv=src.main:main",
            "nv-ssh=src.modules.ssh:main"
        ],
    },
)
