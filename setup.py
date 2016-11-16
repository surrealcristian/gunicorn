# -*- coding: utf-8 -
#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
import sys

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

from gunicorn import __version__


CLASSIFIERS = [
    'Development Status :: 4 - Beta',
    'Environment :: Other Environment',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Operating System :: MacOS :: MacOS X',
    'Operating System :: POSIX',
    'Programming Language :: Python',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.2',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Topic :: Internet',
    'Topic :: Utilities',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: Internet :: WWW/HTTP',
    'Topic :: Internet :: WWW/HTTP :: WSGI',
    'Topic :: Internet :: WWW/HTTP :: WSGI :: Server',
    'Topic :: Internet :: WWW/HTTP :: Dynamic Content']

# read long description
with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as f:
    long_description = f.read()

# read dev requirements
fname = os.path.join(os.path.dirname(__file__), 'requirements_test.txt')
with open(fname) as f:
    tests_require = [l.strip() for l in f.readlines()]

if sys.version_info[:2] < (3, 3):
    tests_require.append('mock')

class PyTestCommand(TestCommand):
    user_options = [
        ("cov", None, "measure coverage")
    ]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.cov = None

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = ['tests']
        if self.cov:
            self.test_args += ['--cov', 'gunicorn']
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)

setup(
    name='gunicorn',
    version=__version__,

    description='WSGI HTTP Server for UNIX',
    long_description=long_description,
    author='Benoit Chesneau',
    author_email='benoitc@e-engura.com',
    license='MIT',
    url='http://gunicorn.org',

    classifiers=CLASSIFIERS,
    zip_safe=False,
    packages=find_packages(exclude=['examples', 'tests']),
    include_package_data=True,

    tests_require=tests_require,
    cmdclass={'test': PyTestCommand},

    entry_points="""
    [console_scripts]
    gunicorn=gunicorn.app.wsgiapp:run
    """
)
