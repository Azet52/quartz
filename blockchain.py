#!/usr/bin/env python

import crypto
import datetime
import hashlib

class Transaction:
    def __init__(self, forwarder, receiver, amount, publickey):
        self.forwarder = forwarder
        self.receiver = receiver
        self.amount = amount
        self.publickey = publickey
        self.signature = crypto.sign(str(self))
        self.hashed = hashlib.md5(str(signature)).hexdigest()

    def __str__(self):
        return 'tx {} -> {} : {}\nhash: {}'.format(self.forwarder,
               self.receiver, self.amount, self.hashed)

    def overview():
        return {'forwarder':forwarder, 'receiver':receiver, 'amount': amount,
                'publickey': publickey, 'signature':signature, 'hash': hashed}

class Node:
    def __init__(self, address, publickey):
        self.address = address
        self.publickey = publickey
        self.fingerprint = self.fingerprint()
        self.neighbours = {}

    def add_neighbour(self, node):
        key = node.items()[0][0]
        value = node.items()[0][1]
        self.neighbours[key] = value

    def fingerprint(self):
        return hashlib.md5(self.publickey).hexdigest()

    def overview():
        return {'fingerprint': self.fingerprint, 'address': self.address}

class Block:
    def __init__(self, index, previous_hash):
        self.index = index
        self.timestamp = None
        self.data = None
        self.miner = None
        self.previous_hash = previous_hash
        self.hashed = None
        self.nonce = None
        #self.valid = None


    def proof_of_work(data, miner):
        self.nonce = 0
        h = 0
        condition = False
        while not condition:
            h = hashlib.sha256(str(data) + str(self.nonce) + miner).hexdigest()
            if (int(h[0:6], 16) == 0):
                condition = True
            else:
                self.nonce += 1
        self.hashed = h
        self.miner = miner
        self.data = data
        self.timestamp = str(datetime.datetime.now())

    def __str__(self):
        return 'b({}) at {} : {}\n{} -> {}'.format(str(self.index),
                str(self.timestamp), str(self.data),
                self.previous_hash, self.hashed)

    def overview():
        return {'index': self.index, 'timestamp': str(self.timestamp),
                'previous_hash' : self.previous_hash, 'hash': self.hashed,
                'transaction': self.data.overview(), 'nonce': self.nonce,
                'miner': self.miner}

def genesis_block():
    return Block(0, hashlib.sha256('QuartzGenesis').hexdigest())

def next_block(last):
    nb_index = last.index + 1
    nb_previous_hash = last_block.hashed
    return Block(nb_index, nb_previous_hash)

def verify_proof(data, nonce, miner):
    h = hashlib.sha256(str(data) + str(nonce) + miner).hexdigest()
    return int(h[0:6], 16) == 0
