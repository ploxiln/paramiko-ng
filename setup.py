# Copyright (C) 2003-2008  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA.

import os
from setuptools import setup

longdesc = '''
*paramiko-ng* is a fork of `paramiko <https://pypi.org/project/paramiko/>`_

For changes in releases of this fork, see https://github.com/ploxiln/paramiko-ng/releases

This is a library for making SSH2 connections (client or server).
Emphasis is on using SSH2 as an alternative to SSL for making secure
connections between python scripts.  All major ciphers and hash methods
are supported.  SFTP client and server mode are both supported too.

Required packages:
    Cryptography

The import name is still just ``paramiko``. Make sure the original *paramiko*
is not installed before installing *paramiko-ng* - otherwise pip may report
success even though *paramiko-ng* was not correctly installed.
(Because the import name is the same, installed files can conflict.)

You can also install under the original "paramiko" pip-package-name,
in order to satisfy requirements for other packages::

    PARAMIKO_REPLACE=1 pip install "https://github.com/ploxiln/paramiko-ng/archive/2.8.10.tar.gz#egg=paramiko"

Replace "2.8.10" with the desired version.

To install the latest development version::

    pip install "git+https://github.com/ploxiln/paramiko-ng/#egg=paramiko-ng"

'''  # noqa: E501

name = "paramiko" if os.environ.get('PARAMIKO_REPLACE') else "paramiko-ng"

# Version info -- read without importing
_locals = {}
with open('paramiko/_version.py') as fp:
    exec(fp.read(), None, _locals)
version = _locals['__version__']

setup(
    name=name,
    version=version,
    packages=['paramiko'],
    description="SSH2 protocol library",
    long_description=longdesc,
    author="Jeff Forcier",
    author_email="jeff@bitprophet.org",
    maintainer='Pierce Lopez',
    maintainer_email='pierce.lopez@gmail.com',
    url="https://github.com/ploxiln/paramiko-ng/",
    license='LGPL',
    platforms='Posix; MacOS X; Windows',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: '
        'GNU Library or Lesser General Public License (LGPL)',
        'Operating System :: OS Independent',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    install_requires=[
        'bcrypt>=3',
        'cryptography>=2.6',
    ],
    extras_require={
        'Ed25519': [],  # can be removed in 3.0
        'gssapi': [
            "pyasn1",
            'gssapi;platform_system!="Windows"',
            'pywin32;platform_system=="Windows"',
        ],
    },
)
