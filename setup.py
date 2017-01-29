#!/usr/bin/env python

from setuptools import setup

setup(name='idle',
      version='0.1',
      description='Tool used to encrypt a Docker image layer and securely transfer it to a target host',
      author='Giannis Giannakopoulos',
      author_email='ggian@cslab.ece.ntua.gr',
      url='https://github.com/giagiannis/docker-layer-encryption',
      packages=['idle'],
      package_data={'': ['config.yml']},
      test_suite='tests',
      scripts=['bin/idle-client', 'bin/idle-at-rest-client']
     )
