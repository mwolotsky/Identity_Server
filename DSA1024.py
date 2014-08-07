from Crypto.PublicKey import DSA
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Util import asn1
import sys

#Generate Key Pair
def generateKeys():
    random_gen = Random.new().read
    key = DSA.generate(1024,random_gen)
    seq = asn1.DerSequence()
    seq[:] = [ 0, key.p, key.q, key.g, key.y, key.x ]
    exported_private = "-----BEGIN DSA PRIVATE KEY-----\n%s-----END DSA PRIVATE KEY-----" % seq.encode().encode("base64")
    key = key.publickey()
    seq = asn1.DerSequence()
    seq[:] = [ 0, key.p, key.q, key.g, key.y ]
    exported_public = "-----BEGIN DSA PUBLIC KEY-----\n%s-----END DSA PUBLIC KEY-----" % seq.encode().encode("base64")
    keys = [exported_private,exported_public]
    return keys

def exportKeys():
    random_gen = Random.new().read 
    key = DSA.generate(1024,random_gen)
    seq = asn1.DerSequence()
    seq[:] = [0,key.p,key.q,key.g,key.y,key.x]
    exported_private = "-----BEGIN DSA PRIVATE KEY-----\n%s-----END DSA PRIVATE KEY-----" % seq.encode().encode("base64")
    pubkey = key.publickey()
    seq = asn1.DerSequence()
    seq[:] = [0,pubkey.p,pubkey.q,pubkey.g,pubkey.y]
    exported_public = "-----BEGIN DSA PUBLIC KEY-----\n%s-----END DSA PUBLIC KEY-----" % seq.encode().encode("base64")
    file = open("PrivateDSAKey.pem","w")
    file.write(exported_private)
    file.close()
    file = open("PublicDSAKey.pem","w")
    file.write(exported_public)
    file.close()

def constructDSAPublic(file):
    seq = asn1.DerSequence()
    data = "\n".join(file.strip().split("\n")[1:-1]).decode("base64")
    seq.decode(data)
    p,q,g,y = seq[1:]
    return DSA.construct((y,g,p,q))

def constructDSAPrivate(file):
    seq = asn1.DerSequence()
    data = "\n".join(file.strip().split("\n")[1:-1]).decode("base64")
    seq.decode(data)
    p,q,g,y,x = seq[1:]
    return DSA.construct((y,g,p,q,x))

#Generate a signature given the key and Message to Sign
def signMessage(key,message):
    hash = MD5.new(message).digest()
    #2 is irrelevant
    #print hash
    signature = key.sign(hash,'2')
    return signature

#Verify a signature given the Public Key, Message, and Signature
def verifyMessage(key,message,signature):
    hash = MD5.new(message).digest()
#     print hash 
    try:
        return key.verify(hash,signature)
    except ValueError:
        print "Value Error"
# keys = generateKeys()
# message = "Hello World"
#   
# seq2 = asn1.DerSequence()
# data = "\n".join(keys[0].strip().split("\n")[1:-1]).decode("base64")
# seq2.decode(data)
# p, q, g, y, x = seq2[1:]
# key2 = DSA.construct((y, g, p, q, x))
# 
# seq2 = asn1.DerSequence()
# data = "\n".join(keys[1].strip().split("\n")[1:-1]).decode("base64")
# seq2.decode(data)
# p, q, g, y = seq2[1:]
# key3 = DSA.construct((y, g, p, q))
#   
# signed = signMessage(key2,message)
# print signed
# print verifyMessage(key3,message,signed)