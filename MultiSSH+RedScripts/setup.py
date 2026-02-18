from setuptools import setup, find_packages

setup(
    name="multissh",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "asyncssh>=2.14.0",
        "pyyaml>=6.0",
        "click>=8.1.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "multissh=multissh.cli:main",
        ],
    },
)