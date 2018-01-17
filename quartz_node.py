#!/usr/bin/env python

import blockchain
import crypto
import json
import netifaces
import threading
import socket
from time import sleep
from flask import Flask
from flask import request
from zeroconf import ServiceBrowser, ServiceStateChange, ServiceInfo, Zeroconf

server = Flask(__name__)

quartz = [blockchain.genesis_block()]
temporary_quartz = [blockchain.genesis_block()]
node = None

block_lock = threading.Lock()
tx_lock = threading.Lock()
user_thread = None
# register_thread = None
# block_thread = threading.Thread(name='block', target=process_block)
transaction_thread = None

# .append(t) and pop() are atomic
transactions = []

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
    print '\nWelcome to QuartzBlockchain!' + '\n  balance FINGERPRINT' \
          + '\n  send RECEIVER AMOUNT' + '\n  exit'
    while not end:
        command = raw_input('>> ')
        if 'balance' in command:
            get_balance(node.fing)
        elif 'send' in command:
            elements = command.split()
            advertise_transaction(elements[1], elements[2])
        elif 'exit' in command:
            end = True

def process_transaction():
    while len(transactions) > 0:
        t = transactions.pop()
        if not lock.locked():
            previous_block = temporary_quartz[-1]
            candidate = next_block(previous_block)
            candidate = candidate.proof_of_work(t, miner)
            if not lock.locked():
                advertise_block(candidate)
                lock.acquire()
                block.append(candidate)
                temporary_quartz.append(candidate)
                lock.release()
            else:
                transaction.append(t)
        else:
            transactions.append(t)

# def process_register(browser):
#     sleep(5)
#     browser = ServiceBrowser(zeroconf, "_http._tcp.local.", handlers=[on_service_state_change])

# def process_block():
#


def on_service_state_change(zeroconf, service_type, name, state_change):
    print("\n\nDiscovered service %s" % (name))

    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
    if info:
        print("  Address: %s:%d" % (socket.inet_ntoa(info.address), info.port))
        print("  Server: %s" % (info.server,))
    if info.properties:
        print("  Properties are:")
        fingerprint, address = '', ''
        for key, value in info.properties.items():
            if key == 'fingerprint':
                print '    fingerprint: ' + value
                name = value
            elif key == 'address':
                print '    address: ' + value
                address = value
        if fingerprint != '' and address != '' and node and node.fingerprint != fingerprint:
            node.add_neighbour({fingerprint: address})
            register(address)

def register(address):
    a = node.address  + ':5000' + '/register'
    print ('Registering to: {}'.format(a))
    r = requests.post(a, data=node.overview())
    print(r.status_code, r.reason)

# when transaction is made by node itself
def advertise_transaction(receiver, amount):
    t = Transaction(erprint, receiver, amount, node.publickey)
    add_transaction(t)
    if not transaction_thread.is_alive():
        transaction_thread.start()
    for fingerprint, address in node.neighbours.items():
        a = address  + ':5000' + '/tx'
        r = requests.post(a, data=t.overview())

# when transaction is from system
def advertise_transaction(transaction):
    for fingerprint, address in node.neighbours.items():
        a = address  + ':5000' + '/tx'
        r = requests.post(a, data=transaction.overview())

def advertise_block(block):
    for fingerprint, address in node.neighbours.items():
        a = address  + ':5000' + '/tx'
        r = requests.post(a, data=b.overview())

def get_balance(fingerprint):
    return 0.0

@server.route('/register', methods=['POST'])
def register_node():
    global node
    if request.method == 'POST':
        tx_data = request.get_json()
        transactions.append(tx_data)
    fingerprint = tx_data['fingerprint']
    address = tx_data['address']
    if node == None:
        print 'Love me tender!'
    if node.fingerprint != fingerprint:
        node.add_neighbour({fingerprint: address})
        print 'OBTAINED: register from {} at {}'.format(fingerprint, address)
    return 'Register success!'

@server.route('/tx', methods=['POST'])
def new_transaction():
    if request.method == 'POST':
        tx_data = request.get_json()
        transactions.append(tx_data)

        forwarder = tx_data['forwarder']
        receiver = tx_data['receiver']
        amount = tx_data['amount']
        publickey = tx_data['publickey']
        signature = tx_data['signature']
        hashed = tx_data['hash']

        transaction = Transaction(forwarder, receiver, amount, publickey)
        if has_transaction(transaction):
            # two step verification
            # transaction comes from publickey owner
            condition = crypto.verify(publickey, str(transaction), signature)
            # value can be spend
            # TODO get_balance(fingerprint)

            if condition:
                advertise_transaction(transaction)
                add_transaction(transaction)
                if not transaction_thread.is_alive():
                    transaction_thread.start()
                return 'Transaction registered'
            else:
                return 'Verification fail, requester is a teapot', 418
        else:
            return 'Transaction already registered'

@server.route('/block', methods=['POST'])
def new_block():
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

        transaction = Transaction(forwarder, receiver, amount, publickey)

        # verify proof of work had place and transaction is from publickey owner
        condition = verify_proof(transaction, nonce, miner) and \
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
    zeroconf = Zeroconf()
    address = netifaces.ifaddresses('wlan0')[netifaces.AF_INET][0]['addr']
    publickey = crypto.getKey()
    node = blockchain.Node(address, publickey)
    fingerprint = node.fingerprint
    desc = {'fingerprint': fingerprint, 'address': address}
    info = ServiceInfo("_http._tcp.local.", 'Quartz._http._tcp.local.', socket.inet_aton(address), 5000, 0, 0, desc)

    zeroconf.register_service(info)
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", handlers=[on_service_state_change])
    user_thread = threading.Thread(name='user', target=user_interface)
    user_thread.start()
    transaction_thread = threading.Thread(name='transaction', target=process_transaction)

    server.run('0.0.0.0')


if __name__ == "__main__":
    main()

#     finally:
#         zeroconf.unregister(info)
#         zeroconf.close()
#         server.close()



#

#def get_users():

#def get_balance():
