#AES-128 CTR Mode implementation
from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Util import Counter
from Crypto.Hash import MD5

#Input Message to encrypt, output a list of keys, [CipherText, AESKey, Initial Counter Value]
def AES_128_Encrypt(message):
    randkey = "%d" % random.getrandbits(128)
    KEY = MD5.new(randkey).hexdigest()
    IV = "%d" %  random.getrandbits(128)
    ctr = Counter.new(128, initial_value=long(IV.encode("hex"), 16))
    cipher = AES.new(KEY,AES.MODE_CTR,counter=ctr)
    ciphertext = cipher.encrypt(message)
    COUNTER = long(IV.encode("hex"),16)
    return [ciphertext, KEY,COUNTER]

def exportKey():
    randkey = "%d" % random.getrandbits(128)
    KEY = MD5.new(randkey).hexdigest()
    IV = "%d" % random.getrandbits(128)
    ctr = Counter.new(128,initial_value=long(IV.encode("hex"),16))
    COUNTER = long(IV.encode("hex"),16)
    return "{}:{}".format(KEY,COUNTER)
    
def encrypt(message,key):
    info = key.split(":")
    KEY = info[0]
    COUNTER = info[1]
    ctr = Counter.new(128,initial_value=COUNTER)
    cipher = AES.new(KEY,AES.MODE_CTR,counter=ctr)
    return cipher.encrypt(message)

def decrypt(ciphertext,key):
    info = key.split(":")
    KEY = info[0]
    COUNTER = info[1]
    ctr = Counter.new(128,initial_value=COUNTER)
    decipher = AES.new(KEY,AES.MODE_CTR,counter=ctr)
    return decipher.decrypt(ciphertext)

#Input CipherText to decrypt, Key and Initial Counter Value
def AES_128_Decrypt(ciphertext, KEY, COUNTER):
    ctr = Counter.new(128,initial_value=COUNTER)
    decipher = AES.new(KEY,AES.MODE_CTR,counter=ctr)
    plaintext = decipher.decrypt(ciphertext)
    return plaintext

def passToKey(password):
    key = password[0:32]
    iv = password[8:40]
    KEY = MD5.new(key).hexdigest()
    ctr = Counter.new(128,initial_value=long(iv.encode("hex"),16))
    COUNTER = long(iv.encode("hex"),16)
    return "{}:{}".format(KEY,COUNTER)
            
