from setuptools import setup, find_packages

setup(
    name="AuthSec_SDK",
    version="4.0.7",
    description="AuthSec SDK for MCP_AUTH, SERVICES, and SPIRE integration",
    author="AuthSec Team",
    email="a@authnull.com",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "aiohttp",
        "asyncpg",
        "psutil",
        "asyncpgsa",
        "grpcio>=1.60.0",
        "protobuf>=5.29.0,<6.0.0"
    ],
    python_requires=">=3.10.11",
)