import os
import hashlib

import random

def generate_challenge():
    return os.urandom(16).hex()

def hash_response(password, challenge):
    combined = password + challenge
    return hashlib.sha256(combined.encode()).hexdigest()

def generate_otp():
    return str(random.randint(100000, 999999))