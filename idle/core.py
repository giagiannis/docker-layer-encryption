#!/usr/bin/python
__all__ = ['DockerDriver', 'EncryptionManager', 'AtRestEncryptionManager']

from os import popen
from Crypto.Cipher import AES

class DockerDriver:
    """
    Class used to interact with Docker
    """
    DOCKER_INSTALLATION_PATH="/var/lib/docker/"
    DOCKER_STORAGE_BACKEND="overlay"   # only work for AUFS for now
    def __init__(self, container_id):
        """
        Default constructor
        """
        self.__container_id = container_id

    def get_topmost_layer_id(self):
        """
        Returns the layers for the speficied container
        """
        file_to_open = DockerDriver.DOCKER_INSTALLATION_PATH+"image/"+DockerDriver.DOCKER_STORAGE_BACKEND+"/layerdb/mounts/"+self.__container_id+"*/init-id"
        path = popen("ls "+file_to_open).read().rstrip()
        layer_id = file(path).read().replace("-init","")
        return layer_id

    def get_topmost_layer_path(self):
        """
        Returns the path of the topmost layer for the specified container
        """
        return DockerDriver.DOCKER_INSTALLATION_PATH+DockerDriver.DOCKER_STORAGE_BACKEND+"/"+self.get_topmost_layer_id()+"/upper/"

    def create_topmost_layer_archive(self, output=None):
        """
        Returns an archive with the data of the topmost layer
        """
        if output is None:
            output = "/tmp/foo.tar"
        foo = popen("tar cf "+output+" -C "+self.get_topmost_layer_path()+" .").read()
        return foo==""

    def deploy_topmost_layer_archive(self, archive):
        foo = popen("tar xf "+archive+" -C "+self.get_topmost_layer_path()).read()
        return foo==""


class EncryptionManager:
    """
    Class used to perform the encryption, decryption and verification functions
    """
    def __init__(self):
        """
        Default constructor
        """
        pass

    def encrypt(self):
        pass

    def decrypt(self):
        pass

    def sign(self):
        pass

    def verify(self):
        pass


class AtRestEncryptionManager:
    """
    Class used to execute the data-at-rest encryption, using ecryptfs
    """
    def __init__(self):
        """
        Default constructor
        """
        raise NotImplemented
