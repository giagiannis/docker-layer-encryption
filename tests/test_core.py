#!/usr/bin/python
import unittest
import random
from os import system,popen
from idle.core import DockerDriver
from idle.core import EncryptionDriver
from ecdsa import SigningKey, VerifyingKey
from .utils import random_hex_string


class DockerDriverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DockerDriverTest.TAR_NAME=random_hex_string()
        DockerDriverTest.TAR_NAME="/tmp/"+DockerDriverTest.TAR_NAME

    @classmethod
    def tearDownClass(cls):
        popen("rm "+ DockerDriverTest.TAR_NAME)

    def setUp(self):
        container_id = popen("docker ps --all | tail  -n 1  | awk '{print $1}'").read().rstrip()
        self.__driver = DockerDriver(container_id)

    def test_get_layers(self):
        layer_id = self.__driver.get_topmost_layer_id()
        assert(layer_id != "")

    def test_get_topmost_layer_path(self):
        path = self.__driver.get_topmost_layer_path()
        assert("-init" not in path)

    def test_create_topmost_layer_archive(self):
        success = self.__driver.create_topmost_layer_archive(DockerDriverTest.TAR_NAME)
        assert(success)

    def test_deploy_topmost_layer_archive(self):
        popen("echo Synthetic > /tmp/file1.txt && tar rf "+DockerDriverTest.TAR_NAME+" -C / tmp/file1.txt")
        success = self.__driver.deploy_topmost_layer_archive(DockerDriverTest.TAR_NAME)
        system("rm /tmp/file1.txt")
        assert(success)

class EncryptionDriverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        EncryptionDriverTest.passphrase  = random_hex_string() 
        EncryptionDriverTest.raw_file = "/tmp/tobeencrypted.txt"
        EncryptionDriverTest.enc_file = "/tmp/encrypted.txt"
        EncryptionDriverTest.contents =  random_hex_string(161)
        file(EncryptionDriverTest.raw_file, 'w').write(EncryptionDriverTest.contents)

    @classmethod
    def tearDownClass(cls):
        system("rm "+EncryptionDriverTest.raw_file)
        system("rm "+EncryptionDriverTest.enc_file)

    def test_encrypt_decrypt(self):
        driver = EncryptionDriver(EncryptionDriverTest.raw_file)
        cipher_file = driver.encrypt(EncryptionDriverTest.passphrase, EncryptionDriverTest.enc_file)
        driver = EncryptionDriver(cipher_file)
        raw_file = driver.decrypt(EncryptionDriverTest.passphrase, EncryptionDriverTest.raw_file)
        assert(file(raw_file).read()==EncryptionDriverTest.contents)

    def test_sign_verify(self):
        sign_key = SigningKey.generate()
        driver = EncryptionDriver(EncryptionDriverTest.raw_file)
        signature = driver.sign(sign_key.to_string())
        verification_key = sign_key.get_verifying_key()
        assert(driver.verify(verification_key.to_string(), signature))


class AtRestEncryptionDriverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_setup(self):
        pass

    def test_status(self):
        pass

    def test_map(self):
        pass

    def test_unmap(self):
        pass
