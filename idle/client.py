#!/usr/bin/python

__all__ = ['IDLEClient']

from idle.core import DockerDriver, EncryptionDriver, AtRestEncryptionDriver
import random
from os import system,remove,popen

class IDLEClient:
    """
    Class used to summarize the functionalities of the IDLE component
    """
    def __init__(self, container_id):
        self.__container_id = container_id

    def export_layer(self, passphrase, sign_key, outfile = None):
        """
        Method used to export the layer containing the confidential data.
        The exported file contains the encrypted data, along with its signature.
        """
        docker = DockerDriver(self.__container_id)
        layer_tar = self.__create_random_path()
        docker.create_topmost_layer_archive(layer_tar)
        encrypted = self.__create_random_path("enc")
        encrypted_tar = EncryptionDriver(layer_tar).encrypt(passphrase, encrypted)
        remove(layer_tar)
        signature = EncryptionDriver(encrypted_tar).sign(sign_key)
        output = self.__create_signed_archive(encrypted, signature, outfile)
        return output

    def install_layer(self, archive_path, passphrase, verification_key):
        """
        Method used to install an encrypted archive into the specified docker container.
        """
        signature, data_path = self.__extract_signed_archive(archive_path)
        encryption_client = EncryptionDriver(data_path)
        if(verification_key is not None):
            v=self.verify_layer(archive_path, verification_key)
            if v==False:
                return False
        raw_data = self.__create_random_path()
        encryption_client.decrypt(passphrase, raw_data)
        docker_driver = DockerDriver(self.__container_id)
        docker_driver.deploy_topmost_layer_archive(raw_data)
        return True

    def verify_layer(self, archive_path, verification_key):
        """
        Method used to verify the integrity of the provided layer. Internally 
        used by the install_layer method, if a verification key is provided
        """
        signature,data_path = self.__extract_signed_archive(archive_path)
        encryption_client = EncryptionDriver(data_path)
        return encryption_client.verify(verification_key, signature)


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

    def __extract_signed_archive(self, archive_path, remove_archive=False):
        """
        Method used to extract the signed archive. The original archive is removed.
        """
        system("cp "+archive_path+" "+archive_path+"-old")
        temp_workspace = self.__create_random_path()
        system("mkdir " + temp_workspace)
        system("tar xfa "+archive_path+" -C "+temp_workspace)
        signature = file(temp_workspace+"/signature").read().rstrip()
        data_path = popen("ls "+temp_workspace+"/*.enc").read().rstrip()
        if not remove_archive:
            system("cp "+archive_path+"-old "+archive_path)
        else:
            system("rm "+archive_path+"-old")

        return signature,data_path


class IDLEAtRestClient:
    def __init__(self, container_id):
        self.__driver = AtRestEncryptionDriver(container_id)

    def setup(self, passphrase):
        return self.__driver.setup(passphrase)

    def map(self, passphrase):
        return self.__driver.map(passphrase)

    def unmap(self):
        return self.__driver.unmap()

    def deactivate_encrypted_disk(self, passphrase = None):
        return self.__driver.deactivate_disk(passphrase)

    def get_status(self):
        return self.__driver.get_status()
