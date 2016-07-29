#!/usr/bin/python
import unittest
import random
from os import system,popen
from idle.core import DockerDriver
from idle.core import EncryptionManager


class DockerDriverTest(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        DockerDriverTest.TAR_NAME=''.join([random.choice("0123456789abdef") for _ in range(10)])+".tar"
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

class EncryptionManagerTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        EncryptionManagerTest.passphrase  = ''.join([random.choice("0123456789abdef") for _ in range(16)]) 
        EncryptionManagerTest.raw_file = "/tmp/tobeencrypted.txt"
        EncryptionManagerTest.enc_file = "/tmp/encrypted.txt"
        EncryptionManagerTest.contents = ''.join([random.choice("0123456789abdef") for _ in range(161)]) 
        file(EncryptionManagerTest.raw_file, 'w').write(EncryptionManagerTest.contents)

    @classmethod
    def tearDownClass(cls):
        system("rm "+EncryptionManagerTest.raw_file)
        system("rm "+EncryptionManagerTest.enc_file)

    def test_encrypt_decrypt(self):
        driver = EncryptionManager(EncryptionManagerTest.raw_file)
        cipher_file = driver.encrypt(EncryptionManagerTest.passphrase, EncryptionManagerTest.enc_file)

        driver = EncryptionManager(cipher_file)
        raw_file = driver.decrypt(EncryptionManagerTest.passphrase, EncryptionManagerTest.raw_file)

        assert(file(raw_file).read()==EncryptionManagerTest.contents)

