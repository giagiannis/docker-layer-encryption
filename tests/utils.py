#!/usr/bin/python
import random

def random_hex_string(length=16):
    return ''.join([random.choice("0123456789abdef") for _ in range(16)]) 

