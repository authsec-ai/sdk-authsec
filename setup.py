from setuptools import setup, find_packages

setup(
    name="AuthSec_SDK",
    version="2.0.0",
    description="AuthSec SDK for MCP_AUTH and SERVICES integration with RBAC support",
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