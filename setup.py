"""Setup configuration for GxP Python Toolkit."""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="gxp-python-toolkit",
    version="1.0.0",
    author="Manuel Knott",
    author_email="manuel.knott@curevac.com",
    description="A comprehensive Python toolkit for GxP-compliant software development",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "examples.*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Healthcare Industry",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Medical Science Apps.",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=[
        "sqlalchemy>=2.0.0",
        "pydantic>=2.0.0",
        "cryptography>=41.0.0",
        "python-jose[cryptography]>=3.3.0",
        "PyJWT>=2.8.0",
        "passlib>=1.7.4",
        "python-dateutil>=2.8.2",
        "pytz>=2023.3",
        "azure-identity>=1.15.0",
        "azure-keyvault-secrets>=4.7.0",
        "azure-keyvault-keys>=4.8.0",
        "azure-mgmt-authorization>=4.0.0",
        "msal>=1.26.0",
        "click>=8.1.0",
        "rich>=13.7.0",
        "tabulate>=0.9.0",
        "pandas>=2.0.0",
        "openpyxl>=3.1.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.4.0",
            "flake8>=6.0.0",
            "pre-commit>=3.3.0",
        ],
        "docs": [
            "sphinx>=7.0.0",
            "sphinx-rtd-theme>=1.3.0",
            "sphinx-autodoc-typehints>=1.24.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "gxp=gxp_toolkit.cli:cli",
        ],
    },
    project_urls={},
)
