#!/usr/bin/python
import unittest
from os import popen
from ecdsa import SigningKey
from .utils import random_hex_string
from idle.client import IDLEClient

class IDLEClientTest(unittest.TestCase):
    def setUp(self):
        self.__container_id = popen("docker ps --all | tail  -n 1  | awk '{print $1}'").read().rstrip()

    def test_export_layer(self):
        client = IDLEClient(self.__container_id)
        key = SigningKey.generate()
        output = client.export_layer(random_hex_string(), key.to_string())
