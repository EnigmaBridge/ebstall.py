import sys

from setuptools import setup
from setuptools import find_packages

version = '0.1.12'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    'ebclient.py>=0.1.20',
    'cmd2>=0.6.9',
    'pycrypto>=2.6',
    'cryptography>=0.7',   # load_pem_x509_certificate
    'parsedatetime>=1.3',  # Calendar.parseDT
    'PyOpenSSL',
    'requests',
    'setuptools>=1.0',
    'sarge>=0.1.4',
    'psutil',
    'pid>=2.0.1',
    'blessed>=1.14.1',
    'coloredlogs',
    'humanfriendly>=2.1',
    'six',
    'future',
    'certbot',
    'certbot-external-auth>=0.0.5',
    'SQLAlchemy',
    'shellescape',
    'jbossply',
    'nginxparser_eb'
]

# env markers in extras_require cause problems with older pip: #517
# Keep in sync with conditional_requirements.py.
if sys.version_info < (2, 7):
    install_requires.extend([
        # only some distros recognize stdlib argparse as already satisfying
        'argparse',
        'mock<1.1.0',
    ])
else:
    install_requires.append('mock')


dev_extras = [
    'nose',
    'pep8',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
    'sphinxcontrib-programoutput',
]


setup(
    name='ebstall',
    version=version,
    description='Enigma Bridge Installer',
    url='https://github.com/EnigmaBridge/ebstall.py',
    author="Enigma Bridge",
    author_email='info@enigmabridge.com',
    license=open('LICENSE').read(),
    long_description=open('README.rst').read(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
    },

    entry_points={
        'console_scripts': [
            'ebstall-cli = ebstall.clirouter:main',
            'ebstall-pki-cli = ebstall.cli:main',
            'ebstall-privspace-cli = ebstall.clivpn:main',
        ],
    }
)
