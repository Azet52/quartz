from Crypto.PublicKey import RSA
import os.path

def getKey():
    f = None
    if os.path.exists('private.key'):
        f = open('private.key', 'r')
        key = RSA.importKey(f.read())
    else:
        key = RSA.generate(2048)
        f = open('private.key', 'w')
        f.write(key.exportKey('PEM'))
    f.close()
    return key.publickey().exportKey(format='OpenSSH')

def sign(message):
    f = open('private.key', 'r')
    key = RSA.importKey(f.read())
    f.close()
    return key.sign(message, 0)[0]

def verify(publickey, message, signature):
    key = RSA.importKey(publickey)
    return RSA.verify(message, (signature,))
