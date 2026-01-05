"""
AAPM Python SDK Setup
"""
from setuptools import setup, find_packages

setup(
    name="aapm",
    version="0.1.0",
    description="AAPM SDK for OpenAI agent monitoring",
    packages=find_packages(),
    install_requires=[
        "openai>=1.0.0",
        "requests>=2.31.0",
    ],
    python_requires=">=3.8",
)

