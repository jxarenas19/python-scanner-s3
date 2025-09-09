"""
Setup script for Scanner → Cifrado local → S3 (MVP)
Document scanner with local encryption and S3 upload
"""

from setuptools import setup, find_packages

setup(
    name="scanner-cifrado-s3",
    version="0.1.0",
    description="Document scanner with local encryption and S3 upload for branch offices",
    author="Delfos Labs",
    author_email="dev@delfoslabs.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=[
        "PyQt6>=6.4.0",
        "cryptography>=41.0.0", 
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "Pillow>=10.0.0",
        "python-dateutil>=2.8.0",
        "pytz>=2023.3",
        "structlog>=23.1.0"
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-qt>=4.2.0", 
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
            "flake8>=6.0.0",
            "pre-commit>=3.0.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "scanner-app=gui.main:main",
            "scanner-cli=cli.scanner_cli:main",
            "crypto-cli=cli.crypto_cli:main", 
            "upload-cli=cli.upload_cli:main",
            "auth-cli=cli.auth_cli:main"
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: End Users/Desktop",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Office/Business :: Financial",
        "Topic :: Security :: Cryptography"
    ],
    keywords="scanner encryption s3 documents security fintech",
)