from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode 

#Return a Public/Private Key Pair
def keyGenerate():
    random_gen = Random.new().read
    key = RSA.generate(1280,random_gen)
    return key

def keyArray():
    random_gen = Random.new().read
    keys = RSA.generate(1280,random_gen)
    private = keys.exportKey()
    pubkey = keys.publickey()
    public = pubkey.exportKey()
    return [private,public]

def exportKeys():
    random_gen = Random.new().read
    keys = RSA.generate(1280,random_gen)
    file = open("PrivateRSAKey.pem","w")
    file.write(keys.exportKey())
    file.close()
    pubkey = keys.publickey()
    file = open("PublicRSAKey.pem","w")
    file.write(pubkey.exportKey())
    file.close()
    
#Encrypt Message with given Public Key
def RSA_Encrypt(message,key):
    rsakey = PKCS1_OAEP.new(key)
    ciphertext = rsakey.encrypt(message)
    
    return ciphertext.encode('base64')

#Decrypt CipherText with given Private Key
def RSA_Decrypt(ciphertext,key):
    rsakey = PKCS1_OAEP.new(key)
    plaintext = rsakey.decrypt(b64decode(ciphertext)) 
    return plaintext
