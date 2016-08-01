#!/usr/bin/python
__all__ = ['DockerDriver', 'EncryptionDriver', 'AtRestEncryptionDriver']

from os import popen
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from ecdsa import SigningKey,VerifyingKey
import random

class DockerDriver:
    """
    Class used to interact with Docker
    """
    DOCKER_INSTALLATION_PATH="/var/lib/docker/"
    DOCKER_STORAGE_BACKEND="overlay"   # only work for overlayfs for now
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

    def create_topmost_layer_archive(self, output):
        """
        Returns an archive with the data of the topmost layer
        """
        foo = popen("tar cf "+output+" -C "+self.get_topmost_layer_path()+" .").read()
        return foo==""

    def deploy_topmost_layer_archive(self, archive):
        foo = popen("tar xf "+archive+" -C "+self.get_topmost_layer_path()).read()
        return foo==""


class EncryptionDriver:
    """
    Class used to perform the encryption, decryption and verification functions
    """
    def __init__(self, input_file):
        """
        Default constructor
        """
        self.__input = input_file

    def encrypt(self, passphrase, output=None):
        """
        Function used to encrypt the input file. Returns the file containing the ciphertext to the user.
        """
        obj = AES.new(passphrase, AES.MODE_CBC, b'0123456789abcdef')
        file_cont = file(self.__input).read()
        bytes_to_pad = 16 - len(file_cont) % 16
        file_cont += bytes_to_pad*chr(bytes_to_pad)
        ciphertext = obj.encrypt(file_cont)

        if output is None:
            output  = '/tmp/'+''.join([random.choice("0123456789abdef") for _ in range(16)])
        file(output, 'w').write(b64encode(ciphertext))
        return output

    def decrypt(self, passphrase, output=None):
        """
        Function used to decrypt the file containing the ciphertext. Returns the raw file path to the user
        """
        obj = AES.new(passphrase, AES.MODE_CBC, b'0123456789abcdef')
        file_cont = file(self.__input).read()
        file_cont = b64decode(file_cont)
        file_cont= obj.decrypt(file_cont)

        bytes_padded = ord(file_cont[len(file_cont)-1])
        file_cont = file_cont[:-bytes_padded]
        if output is None:
            output  = '/tmp/'+''.join([random.choice("0123456789abdef") for _ in range(16)])
        file(output, 'w').write(file_cont)
        return output

    def sign(self, sign_key):
        """
        Method used to sign the input file, based on a signature (private) key.
        """
        key = SigningKey.from_string(sign_key)
        message = file(self.__input).read()
        sig = key.sign(message)
        return b64encode(sig)

    def verify(self, verification_key, signature):
        """
        Method used to verify the input file, based on a verification (public) key and a previously provided signature.
        """
        signature = b64decode(signature)
        key = VerifyingKey.from_string(verification_key)
        message = file(self.__input).read()
        try:
            key.verify(signature, message)
            return True
        except:
            return False


class AtRestEncryptionDriver:
    """
    Class used to execute the data-at-rest encryption, using ecryptfs
    """
    def __init__(self, container_id):
        """
        Default constructor
        """
        self.__container_id = container_id
        self.__docker_driver = DockerDriver(container_id)

    def setup(self, passphrase):
        """
        Method used to allocate, encrypt, project and mount a block device, dedicated for storing the data
        of the topmost container layer. 
        """
        loop_device = self.__create_loop_device()
        self.__luks_format_device(loop_device)
        self.__luks_open_device(loop_device)

    def status(self):
        """
        Checks whether the encrypted device(s) are mounted
        """
        pass
    
    def map(self, passphrase):
        """
        Creates the encryption/decryption mappings
        """
        pass

    def unmap(self):
        """
        Destroys the encryption/decryption mappings 
        pass
        """

    def __create_loop_device(self):
        """
        Function used to generate a file and project it as a loop device. 
        Returns the absolute path of the block device.
        """
        pass

    def __luks_format_device(self, loop_device):
        """
        Format the device (luksFormat+mkfs)
        """
        pass

    def __luks_open_device(self):
        """
        Creates the mapping between the encrypted block device and the container layer
        """
        pass

    def __luks_close_device(self):
        """
        Destroys the mapping
        """
        pass
