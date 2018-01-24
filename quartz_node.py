#!/usr/bin/python3
# -*- coding: utf-8 -*-

import blockchain
import crypto
import json
import netifaces
import threading
import requests
import socket
import zeroconf_listener
from time import sleep
from flask import request
from flask import Flask
from zeroconf import ServiceBrowser, ServiceStateChange, ServiceInfo, Zeroconf

server = Flask(__name__)

quartz = [blockchain.genesis_block()]
temporary_quartz = [blockchain.genesis_block()]
node = None

lock = threading.Lock()
# tx_lock = threading.Lock()
user_thread = None
# register_thread = None
# block_thread = threading.Thread(name='block', target=process_block)
transaction_thread = None

# .append(t) and pop() are atomic
transactions = []
own_transactions = []

def add_transaction(transaction):
    if not has_transaction(transaction):
        transactions.append(transaction)

def has_transaction(transaction):
    for t in transactions:
        if transaction.hashed == t.hashed:
            return True
    return False

def add_block(block):
    if block.index == (len(quartz) - 1) and block.previous_hash == quartz[-1].hashed:
        block.append(block)
        temporary_quartz.append(block)

def user_interface():
    sleep(10)
    end = False
    print ('\nWelcome to QuartzBlockchain!' + '\n  balance FINGERPRINT' \
          + '\n  send RECEIVER AMOUNT' + '\n  exit')
    while not end:
        command = input('>> ')
        if 'balance' in command:
            get_balance(node.fingerprint)
        elif 'neighbours' in command:
            print(node.neighbours)
        elif 'send' in command:
            elements = command.split()
            adv_tx(elements[1], elements[2])
        elif 'exit' in command:
            end = True

def process_transaction():
    global lock
    global node
    while len(transactions) > 0:
        t = transactions.pop()
        if t.forwarder == node.fingerprint:
            own_transactions.append(t)
        else:
            if not lock.locked():
                previous_block = temporary_quartz[-1]
                candidate = blockchain.next_block(previous_block)
                print("POW incoming!")
                candidate.proof_of_work(t, node.fingerprint)
                if not lock.locked():
                    print("POW done!")
                    print(candidate.overview())
                    advertise_block(candidate)
                    lock.acquire()
                    quartz.append(candidate)
                    temporary_quartz.append(candidate)
                    lock.release()
                else:
                    print("Scheduling transaction!")
                    transaction.append(t)
            else:
                transactions.append(t)

def register(address, fngr, addr):
    global node
    a = 'http://' + address  + ':5000' + '/register'
    b = a.encode('utf-8')
    print(b)
    print ('Registering to: {}'.format(a))
    r = requests.post(a, json={'fingerprint':fngr, 'address': addr})
    print(r.status_code, r.reason)

# when transaction is made by node itself
def adv_tx(receiver, amount):
    global node
    global transaction_thread
    print(node.overview())
    t = blockchain.Transaction(node.fingerprint, receiver, amount, node.publickey)
    add_transaction(t)
    if not transaction_thread.is_alive():
        transaction_thread = threading.Thread(name='transaction', target=process_transaction)
        transaction_thread.start()
    for fingerprint, address in node.neighbours.items():
        a = 'http://' + address  + ':5000' + '/tx'
        r = requests.post(a, json=t.overview())

# when transaction is from system
def advertise_transaction(transaction):
    global node
    for fingerprint, address in node.neighbours.items():
        a = 'http://' + address  + ':5000' + '/tx'
        r = requests.post(a, json=transaction.overview())

def advertise_block(block):
    global node
    for fingerprint, address in node.neighbours.items():
        a = 'http://' + address  + ':5000' + '/block'
        r = requests.post(a, json=block.overview())

def get_balance(fingerprint):
    return 0.0

@server.route('/register', methods=['POST'])
def register_node():
    global node

    if request.method == 'POST':
        tx_data = request.get_json()
        # transactions.append(tx_data)
        print(str(tx_data))
        fingerprint = tx_data['fingerprint']
        address = tx_data['address']
        if node == None:
            print('Love me tender!')
        if node.fingerprint != fingerprint:
            node.add_neighbour(fingerprint, address)
            print('OBTAINED: register from {} at {}'.format(fingerprint, address))
    return 'Register success!'

@server.route('/tx', methods=['POST'])
def new_transaction():
    if request.method == 'POST':
        tx_data = request.get_json()

        forwarder = tx_data['forwarder']
        receiver = tx_data['receiver']
        amount = tx_data['amount']
        publickey = tx_data['publickey']
        signature = tx_data['signature']
        hashed = tx_data['hash']

        transaction = blockchain.Transaction(forwarder, receiver, amount, publickey)
        print("Checking: " + str(transaction.overview()))
        if not has_transaction(transaction):
            # two step verification
            # transaction comes from publickey owner
            condition = crypto.verify(publickey, str(transaction), signature)
            print ('tx condition: ' + str(condition))
            # value can be spend
            # TODO get_balance(fingerprint)

            if condition:
                advertise_transaction(transaction)
                add_transaction(transaction)
                if not transaction_thread.is_alive():
                        transaction_thread = threading.Thread(name='transaction', target=process_transaction)
                    transaction_thread.start()
                return 'Transaction registered'
            else:
                return 'Verification fail, requester is a teapot', 418
        else:
            return 'Transaction already registered'

@server.route('/block', methods=['POST'])
def new_block():
    global lock
    lock.acquire()
    if request.method == 'POST':
        tx_data = request.get_json()
        transactions.append(tx_data)

        index = tx_data['index']
        timestamp = tx_data['timestamp']
        previous_hash = tx_data['previous_hash']
        hashed = tx_data['hash']
        nonce = tx_data['nonce']
        miner = tx_data['miner']

        forwarder = tx_data['transaction']['forwarder']
        receiver = tx_data['transaction']['receiver']
        amount = tx_data['transaction']['amount']
        publickey = tx_data['transaction']['publickey']
        signature = tx_data['transaction']['signature']
        hashed = tx_data['transaction']['hash']

        transaction = blockchain.Transaction(forwarder, receiver, amount, publickey)
        print(blockchain.verify_proof(transaction, nonce, miner))
        print(crypto.verify(publickey, str(transaction), signature))
        # verify proof of work had place and transaction is from publickey owner
        condition = blockchain.verify_proof(transaction, nonce, miner) and \
                    crypto.verify(publickey, str(transaction), signature)

        if condition:
            advertise_block(block)
            #node.add_transaction(transaction)
            add_block(block)
            lock.release()
            return 'Transaction registered'
        else:
            return 'Verification fail, requester is a teapot', 418
    else:
        lock.release()


def main():
    global node
    global transaction_thread
    zeroconf = Zeroconf()
    address = netifaces.ifaddresses('wlan0')[netifaces.AF_INET][0]['addr']
    publickey = crypto.getKey()
    node = blockchain.Node(address, publickey)
    print(node.overview())
    fingerprint = node.fingerprint
    desc = {'fingerprint': fingerprint, 'address': address}
    print (desc)
    print (address)
    name = 'quartz_' + socket.gethostname()
    info = ServiceInfo("_http._tcp.local.", name + '._http._tcp.local.', socket.inet_aton('127.0.0.1'), 5001, 0, 0, desc)

    zeroconf.register_service(info)

    listener = zeroconf_listener.ZeroconfListener(node)
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)

    user_thread = threading.Thread(name='user', target=user_interface)
    user_thread.start()
    transaction_thread = threading.Thread(name='transaction', target=process_transaction)

    server.run('0.0.0.0')

    # finally:
    #     zeroconf.unregister(info)
    #     zeroconf.close()
    #     server.close()

if __name__ == "__main__":
    main()
