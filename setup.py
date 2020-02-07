"""
cb-defense-syslog
"""

from setuptools import setup
import sys
import os


install_requires=[
    'Jinja2>=2.8.1',
    'MarkupSafe==1.1.1',
    'requests==2.22.0',
    'Flask==1.1.1'
]

packages=[
    'cb_defense_syslog',
    'cb_defense_syslog.root',
    # 'cb_defense_syslog.root.usr.share.cb.integrations.cb-defense-syslog',
    # #'cb_defense_syslog.root.etc',
    # 'cb_defense_syslog.root.etc.cb.integrations.cb-defense-syslog'



]

scripts = ['src/cb_defense_syslog/root/usr/share/cb/integrations/cb-defense-syslog/cacert.pem',
           'src/cb_defense_syslog/root/etc/cron.d/cb-defense-syslog',
           'src/cb_defense_syslog/root/etc/cb/integrations/cb-defense-syslog/cb-defense-syslog.conf.example'
           ]

setup(
        name='cb_defense_syslog',
        version='0.0.5',
        package_dir={'': 'src'},
        packages=packages,
        include_package_data=True,
        url='https://github.com/carbonblack/cb-defense-syslog-tls',
        license='MIT',
        author='Carbon Black Developer Network',
        author_email='cb-developer-network@vmware.com',
        description=
        'Connector for Cb Defense to send notifications to a tcp+tls host',
        #data_files=data_files,
        install_requires=install_requires,
        classifiers=[
            'Development Status :: 4 - Beta',

            # Indicate who your project is intended for
            'Intended Audience :: Developers',

            # Pick your license as you wish (should match "license" above)
            'License :: OSI Approved :: MIT License',

            # Specify the Python versions you support here. In particular, ensure
            # that you indicate whether you support Python 2, Python 3 or both.
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 2.6',
            'Programming Language :: Python :: 2.7',
        ],
        keywords='carbonblack',
        scripts= scripts
)