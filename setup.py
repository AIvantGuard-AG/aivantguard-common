# AIOneGuardChain - Setup
from setuptools import setup, find_namespace_packages

long_description = open("README.md", "r", encoding="utf-8").read()
setup(
    name="aivantguard-common",
    version="1.0.0.1",
    description="AIvantGuard - Common library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Laszlo Popovics",
    author_email="laszlo@aivantguard.com",
    url="https://github.com/AIvantGuard-AG/aivantguard-common",
    packages=find_namespace_packages(include=["aivantguard-common.*"]),
    classifiers=[
        "Programming Language :: Python :: 3", "License :: MIT", "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    install_requires=['liboqs-python', 'argon2-cffi', 'pycryptodome', 'cryptography', 'pynacl'],
    license="MIT",
    license_files=["LICENSE"],
    include_package_data=True,
)
