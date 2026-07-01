"""Setup script for PQC Readiness Scanner."""

from setuptools import setup, find_packages

setup(
    name="pqc-scanner",
    version="0.1.0",
    description="Post-Quantum Cryptography readiness assessment tool",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="PQC Readiness Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
    ],
    entry_points={
        "console_scripts": [
            "pqc-scanner=pqc_scanner.__main__:cli",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
    ],
)
