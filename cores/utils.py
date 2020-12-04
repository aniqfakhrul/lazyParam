import random
import string

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def encode(string):
    return string.encode('utf-8')

def decode(string):
    return string.decode('utf-8')