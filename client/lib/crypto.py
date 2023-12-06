from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES

from .io import *

# SOURCE: https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt_aes(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # print("padded:", raw)
    raw = raw.encode('utf-8')
    return cipher.encrypt(raw), iv
  
def decrypt_aes(enc, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc)
    return unpad(decrypted).decode()

def genKey():
    return RSA.generate(2048)

def importKey(fname):
    keyData = readFile(fname)
    return RSA.importKey(keyData)

def exportKey(private_key, fname):
    public_key = private_key.public_key()
    pubFname = fname+".pub"
    privFname = fname
    # Save the RSA key in PEM format  
    with open(privFname, "wb") as f:
        f.write(private_key.export_key('PEM'))
  
    # Save the Public key in PEM format  
    with open(pubFname, "wb") as f:
        f.write(public_key.export_key('PEM'))
            
def decryptRsaData(encrypted, key):
    decipher = Cipher_PKCS1_v1_5.new(key)
    raw = decipher.decrypt(encrypted, None)
    return decipher.decrypt(encrypted, None).decode()
    
def encryptData(data, key):
    data = str(data)
    cipher = Cipher_PKCS1_v1_5.new(key)
    return cipher.encrypt(data.encode())
