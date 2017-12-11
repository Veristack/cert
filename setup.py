#!/usr/bin/env python
# -*- coding: utf8 -*-

from distutils.core import setup, Extension
from setuptools import find_packages


with open('requirements.txt') as f:
    required = f.read().splitlines()

required = [r for r in required if not r.startswith('git')]


setup(
    name='cert',
    version='1.0',
    install_requires=required,
    description='A framework for reading and writing certs.',
    author='Ben Timby',
    author_email='btimby@smartfile.com',
    url='https://veristack.com/',
    platforms='OS Independent',
    packages=find_packages(),
    package_data={
        '': ['README.rst', 'requirements.txt']
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Other Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries'
    ]
)
