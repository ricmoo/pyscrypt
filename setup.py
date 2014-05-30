#!/usr/bin/env python

from distutils.core import setup

LONG_DESCRIPTION = '''A very simple, pure-Python implementation of the scrypt
password-based key derivation function and scrypt file format library with no
dependencies beyond standard Python libraries. See README.md for API
reference and details.'''

setup(name = 'pyscrypt',
      version = '1.3.1',
      description = 'Pure-Python Implementation of the scrypt password-based key derivation function and scrypt file format library',
      long_description = LONG_DESCRIPTION,
      author = 'Richard Moore',
      author_email = 'pyscrypt@ricmoo.com',
      url = 'https://github.com/ricmoo/pyscrypt',
      packages = ['pyscrypt'],
      classifiers = [
          'Topic :: Security :: Cryptography',
          'License :: OSI Approved :: MIT License',
      ],
      license = "License :: OSI Approved :: MIT License",
     )
