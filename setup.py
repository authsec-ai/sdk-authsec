from setuptools import setup, find_packages

setup(
    name="AuthSec_SDK",
    version="3.4.0",
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
        "asyncpgsa"
    ],
    python_requires=">=3.10.11",
)