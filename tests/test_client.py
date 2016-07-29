#!/usr/bin/python
import unittest
from os import popen
from ecdsa import SigningKey
from .utils import random_hex_string
from idle.client import IDLEClient

class IDLEClientTest(unittest.TestCase):
    def setUp(self):
        self.__container_id = popen("docker ps --all | tail  -n 1  | awk '{print $1}'").read().rstrip()
    
    def tearDown(self):
        pass

    def test_export_layer(self):
        client = IDLEClient(self.__container_id)
        key = SigningKey.generate()
        passphrase = random_hex_string()
        verification_key = key.get_verifying_key().to_string()
        output = client.export_layer(passphrase, key.to_string())
        assert(client.install_layer(output, passphrase, verification_key))
