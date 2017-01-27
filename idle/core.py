#!/usr/bin/python
__all__ = ['DockerDriver', 'EncryptionDriver', 'BaseAtRestEncryptionDriver', 'FileAtRestEncryptionDriver', 'OpenstackAtRestEncryptionDriver']

from os import popen,system,path,chdir,getcwd
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from ecdsa import SigningKey,VerifyingKey
import random
from time import sleep
from enum import Enum
try:
    import shade
except ImportError:
    print "Warning: Shade module not found"

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


class BaseAtRestEncryptionDriver(object):
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
        if self.get_status()!=BaseAtRestEncryptionDriver.Status.UNENCRYPTED:
            return False
        return True

    def get_status(self):
        """
        Checks whether the encrypted device(s) are mounted
        """
        return True

    def map(self, passphrase):
        """
        Creates the encryption/decryption mappings
        """
        if self.get_status()!=BaseAtRestEncryptionDriver.Status.OFFLINE:
            return False
        return True

    def unmap(self):
        """
        Destroys the encryption/decryption mappings 
        """
        if self.get_status()!=BaseAtRestEncryptionDriver.Status.ONLINE:
            return False
        return True

    def deactivate_disk(self, passphrase=None):
        """
        Erases the encrypted disk file. If the passphrase is provided, the encrypted device is mounted one last time to transfer the data of the layer into the unencrypted directory, else the device is list without backing up the data. 
        """
        if self.get_status()!=BaseAtRestEncryptionDriver.Status.OFFLINE:
            return False
        if passphrase is not None:
            if not self.map(passphrase):
                return False
            layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
            system("mkdir %s_old" % layer_path)
            system("rsync -au %s/ %s_old/" % (layer_path,layer_path))
            if not self.unmap():
                return False
            system("rsync -au %s_old/ %s/" % (layer_path, layer_path))
            system("rm -r %s_old/" % layer_path)
        return True

    # aux methods
    def _docker_mount_device(self):
        """
        Mounts topmost docker layer
        """
        layer_id = self.__docker_driver.get_topmost_layer_id()
        layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
        system("mount /dev/mapper/%s %s" % (layer_id, layer_path))
    
    def _docker_umount_device(self):
        """
        Unmounts topmost docker layer
        """
        layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
        system("umount %s" % layer_path)

    def _docker_format_device(self):
        """
        Formats topmost docker layer
        """
        root_fs_type = popen("df -T %s | awk '{print $2}' | tail -n 1" % self.__docker_driver.DOCKER_INSTALLATION_PATH).read().rstrip()
        system("mkfs.%s -q /dev/mapper/%s" % (root_fs_type, self.__docker_driver.get_topmost_layer_id()))

    def _docker_transfer_old_data(self):
        """
        Transfers existing data to new storage medium
        """
        layer_path = self.__docker_driver.get_topmost_layer_path(data=False)
        system("mv %s %s_old" % (layer_path, layer_path))
        system("mkdir %s" % layer_path)
        self._docker_mount_device()
        system("rsync -au %s_old/ %s/" % (layer_path, layer_path))
        system("rm -r %s_old" % layer_path)

    def _luks_format_device(self, device, passphrase):
        """
        Format the device (luksFormat+mkfs)
        """
        popen("echo -n '%s' | cryptsetup luksFormat %s -" % (passphrase, device))

    def _luks_open_device(self, device, passphrase):
        """
        Creates the mapping between the encrypted block device and the container layer
        """
        popen("echo %s | cryptsetup luksOpen %s %s" % (passphrase, device, self.__docker_driver.get_topmost_layer_id()))

    def _luks_close_device(self):
        """
        Destroys the mapping
        """
        popen("cryptsetup luksClose %s" % self.__docker_driver.get_topmost_layer_id())


class FileAtRestEncryptionDriver(BaseAtRestEncryptionDriver):
    """
    Class used to execute the data-at-rest encryption, using ecryptfs
    """
    def setup(self, passphrase):
        """
        Method used to allocate, encrypt, project and mount a block device, dedicated for storing the data of the topmost container layer. 
        """
        if not super(FileAtRestEncryptionDriver, self).setup(passphrase):
            return False
        
        self.__attach_loop_device(create_device=True)
        sleep(.2)
        self._luks_format_device(self.__get_mapper_partition(), passphrase)
        self._luks_open_device(self.__get_mapper_partition(), passphrase)
        self._docker_format_device()
        
        # transfer existing data to the new storage medium
        self._docker_transfer_old_data()
        sleep(.2)
        return True

    def get_status(self):
        """
        Checks whether the encrypted device(s) are mounted
        """
        if not super(FileAtRestEncryptionDriver, self).get_status():
            return None

        if not path.isfile(self._get_disk_file()):
            return BaseAtRestEncryptionDriver.Status.UNENCRYPTED
        
        if self.__get_mapper_device()=="":
            return super(FileAtRestEncryptionDriver, self).Status.OFFLINE

        return super(FileAtRestEncryptionDriver, self).Status.ONLINE

    def map(self, passphrase):
        """
        Creates the encryption/decryption mappings
        """
        if not super(FileAtRestEncryptionDriver, self).map(passphrase):
            return False
        
        self.__attach_loop_device()
        sleep(.2)
        self._luks_open_device(self.__get_mapper_partition(), passphrase)
        self._docker_mount_device()
        return True
        
    def unmap(self):
        """
        Destroys the encryption/decryption mappings 
        """
        if not super(FileAtRestEncryptionDriver, self).unmap():
            return False
        
        self._docker_umount_device()
        self._luks_close_device()
        self.__detach_loop_device()
        sleep(.2)
        return True

    def deactivate_disk(self, passphrase=None):
        """
        Erases the encrypted disk file. If the passphrase is provided, the encrypted device is mounted one last time to transfer the data of the layer into the unencrypted directory, else the device is list without backing up the data. 
        """
        if not super(FileAtRestEncryptionDriver, self).deactivate_disk(passphrase):
            return False

        system("rm %s" % self.__get_disk_file())
        return True

    # aux methods
    def _get_disk_file(self):
        """
        Returns the disk file path
        """
        return self.__docker_driver.get_topmost_layer_path(data=False)+".disk"

    def __attach_loop_device(self, create_device = False):
        """
        Function used to generate a file and project it as a loop device. 
        Returns the absolute path of the block device.
        """
        if create_device:   # first create the device
            popen("truncate --size 10G %s" % self.__get_disk_file())
        popen("kpartx -a %s" % self.__get_disk_file())

    def __detach_loop_device(self):
        """
        Unmounts previously created loop device
        """
        system("kpartx -d %s" % self.__get_mapper_device())
        system("losetup -D")

    def __get_mapper_device(self):
        """
        Returns the device, e.g., /dev/loop1 - useful for management
        """
        return popen("losetup | grep %s | awk '{print $1}'" % self.__docker_driver.get_topmost_layer_id()).read().rstrip()

    def __get_mapper_partition(self):
        """
        Returns the partition, e.g., /dev/mapper/loop1p1 - useful for writing
        """
        return "/dev/mapper/"+self.__get_mapper_device().split("/")[2]+"p1"
    

class OpenstackAtRestEncryptionDriver(BaseAtRestEncryptionDriver):
    """
    Class used to execute the data-at-rest encryption, using ecryptfs
    """
    def __init__(self, container_id, cloud_config):
        clouds_dir = path.abspath(cloud_config['config_dir']) 
        chdir(clouds_dir)
        self.__cloud = shade.openstack_cloud(cloud='cslab')
        self.__srv_name = cloud_config['server_name']
        self.__vol_name = cloud_config['volume_name']
        super(OpenstackAtRestEncryptionDriver, self).__init__(container_id)

    def setup(self, passphrase):
        """
        Method used to allocate, encrypt, project and mount a block device, dedicated for storing the data of the topmost container layer. 
        """
        if not super(OpenstackAtRestEncryptionDriver, self).setup(passphrase):
            return False
        
        device = self.__attach_openstack_volume(create_device=True)
        self._luks_format_device(device, passphrase)
        self._luks_open_device(device, passphrase)
        self._docker_format_device()
        self._docker_transfer_old_data()
        sleep(.2)
        return True

    def get_status(self):
        """
        Checks whether the encrypted device(s) are mounted
        """
        if not super(OpenstackAtRestEncryptionDriver, self).get_status():
            return None

        if self.__cloud.get_volume(self.__vol_name) == None:
            return super(OpenstackAtRestEncryptionDriver, self).Status.UNENCRYPTED
        
        if self.__get_openstack_volume_device() == None:
            return super(OpenstackAtRestEncryptionDriver, self).Status.OFFLINE

        return super(OpenstackAtRestEncryptionDriver, self).Status.ONLINE


    def map(self, passphrase):
        """
        Creates the encryption/decryption mappings
        """
        if not super(OpenstackAtRestEncryptionDriver, self).map(passphrase):
            return False
        
        self.__attach_openstack_volume()
        sleep(.2)
        self._luks_open_device(self.__get_openstack_volume_device(), passphrase)
        self._docker_mount_device()
        return True
        
    def unmap(self):
        """
        Destroys the encryption/decryption mappings 
        """
        if not super(OpenstackAtRestEncryptionDriver, self).unmap():
            return False
        
        self._docker_umount_device()
        self._luks_close_device()
        self.__detach_openstack_volume()
        sleep(.2)
        return True

    def deactivate_disk(self, passphrase=None):
        """
        Erases the encrypted disk file. If the passphrase is provided, the encrypted device is mounted one last time to transfer the data of the layer into the unencrypted directory, else the device is list without backing up the data. 
        TODO: error checking
        """
        if not super(OpenstackAtRestEncryptionDriver, self).deactivate_disk(passphrase):
            return False
        
        c = self.__cloud
        v = c.get_volume(self.__vol_name)
        c.delete_volume(v.id)
        return True

    # aux methods
    def __attach_openstack_volume(self, size = 1, create_device = False):
        """
        Creates an openstack volume and attaches it to the VM used
        TODO: error checking
        """
        c = self.__cloud
        s = c.get_server(self.__srv_name)
        v = c.get_volume(self.__vol_name)
        if create_device and v == None:
            v = c.create_volume(size, name=self.__vol_name)
        if not v.attachments:
            c.attach_volume(s, v)
            """ Need to get volume again to succesfully get the device name later """
            v = c.get_volume(self.__vol_name)
        return c.get_volume_attach_device(v, s.id)
    
    def __detach_openstack_volume(self):
        """
        Unmounts previously created openstack volume device
        TODO: error checking
        """
        c = self.__cloud
        s = c.get_server(self.__srv_name)
        v = c.get_volume(self.__vol_name)
        c.detach_volume(s, v)

    def __get_openstack_volume_device(self):
        """
        Returns the device name an openstack volume is attached to
        TODO: error checking
        """
        c = self.__cloud
        s = c.get_server(self.__srv_name)
        v = c.get_volume(self.__vol_name)
        return c.get_volume_attach_device(v, s.id)
