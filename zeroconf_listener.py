#!/usr/bin/python3
# -*- coding: utf-8 -*-

from zeroconf import ServiceBrowser, Zeroconf
from time import sleep
import blockchain
import crypto
import quartz_node
import socket

class ZeroconfListener:
    def __init__(self, node):
        self.node = node

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))

    def add_service(self, zeroconf, type, name):
        print("\n\nDiscovered service %s" % (name))
        fingerprint, address = '', ''
        sleep(3)


        info = zeroconf.get_service_info(type, name)
        if info:
            print("  Address: %s:%d" % (socket.inet_ntoa(info.address), info.port))
            print("  Server: %s" % (info.server,))
        if info.properties:
            print("  Properties are:")
            print(info.properties.items())
            for key, value in info.properties.items():
                key = key.decode('utf-8')
                if key == 'fingerprint':
                    fingerprint = value.decode('utf-8')
                    print('    fingerprint: ' + name)
                elif key == 'address':
                    address = value.decode('utf-8')
                    print('    address: ' + address)
            if fingerprint != '' and address != '' and self.node and self.node.address != address:
                self.node.add_neighbour(fingerprint, address)
                quartz_node.register(address, self.node.fingerprint, self.node.address)
