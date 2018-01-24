#!/usr/bin/python3
# -*- coding: utf-8 -*-

#from Cryptodome.PublicKey import RSA
import rsa
import os.path

def getKey():
    f_priv = None
    f_publ = None
    public_key = None
    if os.path.exists('private.key') and os.path.exists('public.key'):
        f_priv = open('private.key', 'r')
        f_publ = open('public.key', 'r')
        public_key = rsa.PublicKey.load_pkcs1(f_publ.read())
    else:
        (public_key, private_key) = rsa.newkeys(2048)
        f_priv = open('private.key', 'w')
        f_publ = open('public.key', 'w')
        f_priv.write(rsa.PrivateKey.save_pkcs1(private_key).decode('utf-8'))
        f_publ.write(rsa.PublicKey.save_pkcs1(public_key).decode('utf-8'))
    f_priv.close()
    f_publ.close()
    return rsa.PublicKey.save_pkcs1(public_key, format='DER').hex()

def sign(message):
    f = open('private.key', 'r')
    private_key = rsa.PrivateKey.load_pkcs1(f.read())
    f.close()
    print('S-MESSAGE:' + str(message.encode('utf-8')))
    print('S-SIGNATURE: ' + rsa.sign(message.encode('utf-8'), private_key, 'SHA-1').hex())
    return rsa.sign(message.encode('utf-8'), private_key, 'SHA-1').hex()

def verify(hexkey, message, signature):
    public_key = rsa.PublicKey.load_pkcs1(bytes.fromhex(hexkey), format='DER')
    print('V-MESSAGE:' + str(message.encode('utf-8')))
    print('V-SIGNATURE: ' + hexkey)
    try:
        rsa.verify(message.encode('utf-8'), bytes.fromhex(signature), public_key)
    except rsa.pkcs1.VerificationError:
        return False
    return True
