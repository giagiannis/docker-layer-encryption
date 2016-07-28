#!/usr/bin/python
__all__ = ['DockerDriver', 'EncryptionManager', 'AtRestEncryptionManager']

from os import popen

class DockerDriver:
    """
    Class used to interact with Docker
    """
    DOCKER_INSTALLATION_PATH="/var/lib/docker/"
    def __init__(self, container_id):
        """
        Default constructor
        """
        self.__container_id = container_id

    def get_layers(self):
        """
        Returns the layers for the speficied container
        """
        file_to_open = DockerDriver.DOCKER_INSTALLATION_PATH+"image/aufs/layerdb/mounts/"+self.__container_id+"*/init-id"
        path = popen("ls "+file_to_open).read().rstrip()
        layer_id = file(path).read().replace("-init","")
        layers = [x.replace("-init", "") for x in file(DockerDriver.DOCKER_INSTALLATION_PATH+"aufs/layers/"+layer_id).read().rstrip().split("\n")]
        return layers

    def get_topmost_layer_path(self):
        """
        Returns the path of the topmost layer for the specified container
        """
        return DockerDriver.DOCKER_INSTALLATION_PATH+"aufs/diff/"+self.get_layers()[0]

    def create_topmost_layer_archive(self, output=None):
        """
        Returns an archive with the data of the topmost layer
        """
        if output is None:
            output = "/tmp/foo.tar"
        foo = popen("tar cf "+output+" -C "+self.get_topmost_layer_path()+" .").read()

    def deploy_topmost_layer_archive(self, archive):
        foo = popen("tar xf "+archive+" -C "+self.get_topmost_layer_path()).read()


class EncryptionManager:
    """
    Class used to perform the encryption, decryption and verification functions
    """
    def __init__(self):
        """
        Default constructor
        """
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
