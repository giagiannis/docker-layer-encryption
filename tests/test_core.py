#!/usr/bin/python
import unittest
import random
from os import system,popen
from idle.core import DockerDriver, EncryptionDriver, AtRestEncryptionDriver
from ecdsa import SigningKey, VerifyingKey
from .utils import random_hex_string, create_docker_container, rm_docker_container, start_docker_container
from time import sleep


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
    def setUp(self):
        self.__container_id = create_docker_container()
        self.__driver = AtRestEncryptionDriver(self.__container_id)
        self.__passphrase = random_hex_string()

    def tearDown(self):
        if self.__driver.get_status()==AtRestEncryptionDriver.Status.ONLINE:
            self.__driver.unmap()
        if self.__driver.get_status()==AtRestEncryptionDriver.Status.OFFLINE:
            self.__driver.destroy_disk()
        if self.__driver.get_status()==AtRestEncryptionDriver.Status.UNENCRYPTED:
            rm_docker_container(self.__container_id)

    def test_deterministic_scenario(self):
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        self.__driver.setup(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        self.__driver.unmap()
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.OFFLINE)
        sleep(0.5)
        self.__driver.map(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        sleep(0.5)
        self.__driver.unmap()
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.OFFLINE)
        self.__driver.destroy_disk()
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)

    def test_setup(self):
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        succeeded = self.__driver.setup(self.__passphrase)
        assert(succeeded)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        succeeded = self.__driver.setup(self.__passphrase)
        assert(not succeeded)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)

    def test_map(self):
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        succeeded = self.__driver.map(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        assert(not succeeded)

        succeeded = self.__driver.setup(self.__passphrase)

        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        succeeded = self.__driver.map(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        assert(not succeeded)

        self.__driver.unmap()
        sleep(0.2)

        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.OFFLINE)
        succeeded = self.__driver.map(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        assert(succeeded)


    def test_unmap(self):
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        succeeded = self.__driver.unmap()
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        assert(not succeeded)

        succeeded = self.__driver.setup(self.__passphrase)

        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        succeeded = self.__driver.unmap()
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.OFFLINE)
        assert(succeeded)

        succeeded = self.__driver.unmap()
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.OFFLINE)
        assert(not succeeded)

    def test_destroy_disk_smooth(self):
        self.__driver.setup(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        self.__driver.unmap()
        self.__driver.destroy_disk(self.__passphrase)
        succeeded = start_docker_container(self.__container_id)
        assert(succeeded)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.UNENCRYPTED)
        
        self.__driver.setup(self.__passphrase)
        assert(self.__driver.get_status() == AtRestEncryptionDriver.Status.ONLINE)
        self.__driver.unmap()
        self.__driver.destroy_disk()
        succeeded = start_docker_container(self.__container_id)
        assert(not succeeded)

