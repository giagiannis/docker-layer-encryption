#!/usr/bin/python
import random
from os import popen
from time import sleep

def random_hex_string(length=16):
    return ''.join([random.choice("0123456789abdef") for _ in range(16)]) 

def create_docker_container():
    container_id=popen("docker  run -d debian /bin/bash -c '/bin/echo foo > /root/bar'").read().rstrip()
    return container_id

def rm_docker_container(container_id):
    popen("docker rm -f "+container_id)
