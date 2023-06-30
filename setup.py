"""cbc-syslog"""

from setuptools import setup
import io

packages = [
    "cbc_syslog",
    "cbc_syslog.util"
]

install_requires = [
    "carbon-black-cloud-sdk",
    "Jinja2",
    "psutil",
    "tomli >= 1.1.0; python_version < '3.11'"
]

extras_require = {
    "test": [
        "flask",
        "cryptography",
        "pytest==7.2.1",
        "coverage==6.5.0",
        "coveralls==3.3.1",
        "flake8==5.0.4",
        "flake8-colors==0.1.9",
        "flake8-docstrings==1.7.0",
        "pre-commit>=2.15.0",
        "freezegun==1.2.2",
    ]
}

with io.open("README.md", "rt", encoding="utf8") as f:
    long_description = f.read()

scripts = ["scripts/cbc_syslog_forwarder.py"]

setup(
    name="cbc_syslog",
    version="2.0.0",
    install_requires=install_requires,
    extras_require=extras_require,
    package_dir={"": "src"},
    include_package_data=True,
    packages=packages,
    scripts=scripts,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/carbonblack/cbc-syslog",
    license="MIT",
    author="Carbon Black Developer Network",
    author_email="cb-developer-network@vmware.com",
    description="Syslog Connector for the Carbon Black Cloud",
    classifiers=[
        # Indicate who your project is intended for
        "Intended Audience :: Developers",

        # Pick your license as you wish (should match "license" above)
        "License :: OSI Approved :: MIT License",

        "Programming Language :: Python :: 3",
    ],
    keywords="carbonblack"
)
