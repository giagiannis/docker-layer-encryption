#!/usr/bin/python
__all__ = ['DockerDriver', 'EncryptionDriver', 'AtRestEncryptionDriver']

from os import popen,system,path
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from ecdsa import SigningKey,VerifyingKey
import random
from time import sleep
from enum import Enum

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

    def get_topmost_layer_path(self, data=True):
        """
        Returns the path of the topmost layer for the specified container. If data is set to True (default operation), the data dir is returned; If data is False, the root layer path (with metadata and util folders) is returned.
        """
        if data:
            return DockerDriver.DOCKER_INSTALLATION_PATH+DockerDriver.DOCKER_STORAGE_BACKEND+"/"+self.get_topmost_layer_id()+"/upper/"
        else:
            return DockerDriver.DOCKER_INSTALLATION_PATH+DockerDriver.DOCKER_STORAGE_BACKEND+"/"+self.get_topmost_layer_id()


    def create_topmost_layer_archive(self, output):
        """
        Returns an archive with the data of the topmost layer
        """
        foo = popen("tar cf "+output+" -C "+self.get_topmost_layer_path()+" .").read()
        return foo==""

    def deploy_topmost_layer_archive(self, archive):
        foo = popen("tar xf "+archive+" -C "+self.get_topmost_layer_path()).read()
        return foo==""

    #def get_layer_storage_path(self):
    #    return self.DOCKER_INSTALLATION_PATH+self.DOCKER_STORAGE_BACKEND


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


    class Status(Enum):
        """
        Status class indicates the status of the AtRestEncryption driver
        """
        UNENCRYPTED = 0,
        OFFLINE = 1,
        ONLINE = 2

    def __init__(self, container_id):
        """
        Default constructor
        """
        self.__container_id = container_id
        self.__docker_driver = DockerDriver(container_id)

    def setup(self, passphrase):
        """
        Method used to allocate, encrypt, project and mount a block device, dedicated for storing the data of the topmost container layer. 
        """
        if self.get_status()!=AtRestEncryptionDriver.Status.UNENCRYPTED:
            return False
        self.__attach_loop_device(create_device=True)
        sleep(.2)
        self.__luks_format_device(passphrase)
        self.__luks_open_device(passphrase)
        root_fs_type = popen("df -T "+self.__docker_driver.DOCKER_INSTALLATION_PATH+"  | awk '{print $2}' | tail -n 1").read().rstrip()
        system("mkfs."+root_fs_type+" -q /dev/mapper/"+self.__docker_driver.get_topmost_layer_id())
        
        # transfer existing data to the new storage medium
        layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
        system("mv "+layer_path+" "+layer_path+"_old")
        system("mkdir "+layer_path)
        system("mount /dev/mapper/"+self.__docker_driver.get_topmost_layer_id()+" "+layer_path)
        system("rsync -au "+layer_path+"_old/ "+layer_path+"/")
        system("rm -r "+layer_path+"_old")
        sleep(.2)
        return True

    def get_status(self):
        """
        Checks whether the encrypted device(s) are mounted
        """
        if not path.isfile(self.__get_disk_file()):
            return AtRestEncryptionDriver.Status.UNENCRYPTED
        if self.__get_mapper_device()=="":
            return AtRestEncryptionDriver.Status.OFFLINE
        return AtRestEncryptionDriver.Status.ONLINE
    
    def map(self, passphrase):
        """
        Creates the encryption/decryption mappings
        """
        if self.get_status()!=AtRestEncryptionDriver.Status.OFFLINE:
            return False
        self.__attach_loop_device()
        sleep(.2)
        self.__luks_open_device(passphrase)
        layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
        system("mount /dev/mapper/"+self.__docker_driver.get_topmost_layer_id()+" "+layer_path)
        return True

        
    def unmap(self):
        """
        Destroys the encryption/decryption mappings 
        """
        if self.get_status()!=AtRestEncryptionDriver.Status.ONLINE:
            return False
        layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
        system("umount "+layer_path)
        self.__luks_close_device()
        system("kpartx -d "+ self.__get_mapper_device())
        system("losetup -D")
        sleep(.2)
        return True

    def deactivate_disk(self, passphrase=None):
        """
        Erases the encrypted disk file. If the passphrase is provided, the encrypted device is mounted one last time to transfer the data of the layer into the unencrypted directory, else the device is list without backing up the data. 
        """
        if self.get_status()!=AtRestEncryptionDriver.Status.OFFLINE:
            return False
        if passphrase is not None:
            self.map(passphrase)
            layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
            system("mkdir "+layer_path+"_old")
            system("rsync -au "+layer_path+"/ "+layer_path+"_old/")
            self.unmap()
            system("rsync -au "+layer_path+"_old/ "+layer_path+"/")
            system("rm -r "+layer_path+"_old")
        system("rm "+self.__get_disk_file())
        return True


    # aux methods
    def __attach_loop_device(self, create_device = False):
        """
        Function used to generate a file and project it as a loop device. 
        Returns the absolute path of the block device.
        """
        if create_device:   # first create the device
            popen("truncate --size 100G "+ self.__get_disk_file())
        popen("kpartx -a "+self.__get_disk_file())

    def __luks_format_device(self, passphrase):
        """
        Format the device (luksFormat+mkfs)
        """
        popen("echo -n '"+passphrase+"' | cryptsetup luksFormat "+self.__get_mapper_partition()+" -")

    def __luks_open_device(self, passphrase):
        """
        Creates the mapping between the encrypted block device and the container layer
        """
        popen("echo "+passphrase+"| cryptsetup luksOpen "+self.__get_mapper_partition()+" "+self.__docker_driver.get_topmost_layer_id())

    def __luks_close_device(self):
        """
        Destroys the mapping
        """
        popen("cryptsetup luksClose "+self.__docker_driver.get_topmost_layer_id())

    def __get_mapper_device(self):
        """
        Returns the device, e.g., /dev/loop1 - useful for management
        """
        return popen("losetup | grep "+self.__docker_driver.get_topmost_layer_id()+" |awk '{print $1}'").read().rstrip()

    def __get_mapper_partition(self):
        """
        Returns the partition, e.g., /dev/mapper/loop1p1 - useful for writing
        """
        return "/dev/mapper/"+self.__get_mapper_device().split("/")[2]+"p1"

    def __get_disk_file(self):
        """
        Returns the disk file path
        """
        return self.__docker_driver.get_topmost_layer_path(data=False)+".disk"
