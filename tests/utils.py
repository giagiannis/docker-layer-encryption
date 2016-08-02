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

def start_docker_container(container_id):
    output = popen("docker start "+ container_id+" 2>&1").read().rstrip()
    succeeded  = (output==container_id)
    if succeeded:
        sink = popen("docker stop "+ container_id+" 2>&1").read().rstrip()
    return succeeded

