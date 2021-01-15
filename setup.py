"""
cbc-syslog
"""

from setuptools import setup
from setuptools import find_packages
import io


install_requires = [
    'Jinja2==2.11.2',
    'requests==2.24.0',
    'psutil==5.7.3',
    ]

packages = [
    'cbc_syslog',
    'cbc_syslog.root'
    ]

with io.open('README.md', 'rt', encoding='utf8') as f:
    long_description = f.read()

scripts = ['src/cbc_syslog/root/usr/share/cb/integrations/cbc-syslog/cacert.pem',
           'src/cbc_syslog/root/etc/cron.d/cbc-syslog',
           'src/cbc_syslog/root/etc/cb/integrations/cbc-syslog/cbc-syslog.conf.example'
           ]

setup(
    name='cbc_syslog',
    version='1.3.1',
    package_dir={'': 'src'},
    packages=find_packages(where="src", exclude=["tests.*", "tests"]),
    include_package_data=True,
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/carbonblack/cbc-syslog',
    license='MIT',
    author='Carbon Black Developer Network',
    author_email='cb-developer-network@vmware.com',
    description='Syslog Connector for the Carbon Black Cloud',
    install_requires=install_requires,
    classifiers=[

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        ],
    keywords='carbonblack',
    scripts=scripts)
