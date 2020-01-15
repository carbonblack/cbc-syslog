"""
cb-defense-syslog
"""

from setuptools import setup
import sys
import os


install_requires=[
    'Jinja2>=2.8.1',
    'MarkupSafe==0.23',
    'requests>=2.20.0',
    'flask==0.12.4',
    'six==1.12.0'
]

def get_data_files(rootdir):
    # automatically build list of (dir, [file1, file2, ...],)
    # for all files under src/root/ (or provided rootdir)
    results = []
    for root, dirs, files in os.walk(rootdir):
        if len(files) > 0:
            dirname = os.path.relpath(root, rootdir)
            flist = [os.path.join(root, f) for f in files]
            results.append(("/%s" % dirname, flist))

    return results

def create_store_directory():
    store_forwarder_dir = 'root/usr/share/cb/integrations/cb-defense-syslog'

    try:
        os.mkdir(store_forwarder_dir)
    except OSError:
        print("Creation of the directory %s failed" % store_forwarder_dir)
    else:
        print("Successfully created the directory %s " % store_forwarder_dir)


data_files = get_data_files("root")
create_store_directory()
data_files.append('cb-defense-syslog.spec')
data_files.append('cb_defense_syslog.py')
scripts = {
    'cb-defense-syslog': {
        'spec': 'cb-defense-syslog.spec',
        'dest': '/usr/share/cb/integrations/cb-defense-syslog/cb-defense-syslog'
    }
}

setup(
        name='python-cb-defense-syslog',
        version='2.0',
        packages=[],
        url='https://github.com/carbonblack/cb-defense-syslog-tls',
        license='MIT',
        author='Carbon Black Developer Network',
        author_email='cb-developer-network@vmware.com',
        description=
        'Connector for Cb Defense to send notifications to a tcp+tls host',
        data_files=data_files,
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
        keywords='carbonblack'
)