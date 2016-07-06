#!/usr/bin/env python

from distutils.core import setup

setup(name='docker-layer-encryption',
      version='0.1',
      description='Tool used to encrypt a Docker image layer and securely transfer it to a target host',
      author='Giannis Giannakopoulos',
      author_email='ggian@cslab.ece.ntua.gr',
      url='https://github.com/giagiannis/docker-layer-encryption',
      packages=['idle']
     )
