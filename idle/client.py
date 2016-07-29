#!/usr/bin/python

__all__ = ['IDLEClient']

from idle.core import DockerDriver, EncryptionDriver
import random
from os import system,remove

class IDLEClient:
    """
    Class used to summarize the functionalities of the IDLE component
    """
    def __init__(self, container_id):
        self.__container_id = container_id

    def export_layer(self, passphrase, sign_key, outfile = None):
        """
        Method used to export the layer containing the confiential data.
        The exported file contains the encrypted data, along with its signature and
        the public key file.
        """
        docker = DockerDriver(self.__container_id)
        layer_tar = self.__create_random_path()
        docker.create_topmost_layer_archive(layer_tar)
        encrypted = self.__create_random_path("enc")
        encrypted_tar = EncryptionDriver(layer_tar).encrypt(passphrase, encrypted)
        remove(layer_tar)
        signature = EncryptionDriver(encrypted_tar).sign(sign_key)
        output = self.__create_signed_archive(encrypted, signature)
        return output

    def install_layer(self):
        """
        Method used to install 
        """
        pass

    def __create_random_path(self, suffix="temp"):
        """
        Generates a random path 
        """
        random_str = ''.join([random.choice("0123456789abdef") for _ in range(10)])
        return "/tmp/"+random_str+"."+suffix

    def __create_signed_archive(self, data_path, signature, output=None):
        """
        Method used to generate an archive containing data along with its
        signature.
        """
        if output is None:
            output = self.__create_random_path("tar.bz2")
        temp_workspace = self.__create_random_path()
        system("mkdir "+temp_workspace)
        system("mv "+data_path+" "+temp_workspace)
        file(temp_workspace+"/signature",'w').write(signature)
        system("tar cfj "+output+" -C "+temp_workspace+" .")
        system("rm -r "+temp_workspace)
        return output
