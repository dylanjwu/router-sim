'''
myrouter.py 

Basic IPv4 router template (static routing) in Python, with ARP implemented.

Carleton CS 331, Fall 2020
Whitman CS 301, Fall 2021
'''

import sys
import os
import time
from collections import namedtuple
from switchyard.lib.userlib import *

class ArpPending(object):
    '''
    This class handles the mechanics of resending ARP requests, and determining
    when an ARP request should time out.
    
    :param str egress_dev: The interface on which to send the packet
    :param IPv4Address nexthop: The IP address of the next hop for the packet
    :param Packet pkt: The packet to send once the MAC address is determined
    '''
    def __init__(self, egress_dev, nexthop, pkt):
        self.egress_dev = egress_dev
        self.nexthop = nexthop
        self.pkt = pkt # packet object with Ethernet header stripped from head
        self.last_update = time.time()
        self.attempts = 0
    
    def can_try_again(self, timestamp):
        '''
        Returns True if we haven't timed out of ARP request attempts yet, 
        and False otherwise.
        '''
        if self.giveup(timestamp):
            return False
        if self.attempts == 0:
            return True
        if (timestamp - self.last_update) >= 1.0:
            return True
        return False

    def add_attempt(self):
        '''
        Accounting method: records the time, and increments the number of attempts,
        each time we re-attempt sending an ARP request.
        '''
        self.last_update = time.time()
        self.attempts += 1

    def giveup(self, timestamp):
        '''
        If we've used up all of our attempts and the timer's expired on the most 
        recent attempt, return True. We will send no more ARP requests.
        '''
        return self.attempts == 5 and (timestamp-self.last_update) >= 1.0

    def __str__(self):
        return "Packet to ARP: {} (nexthop: {}, egress: {}, attempts: {} last: {} now: {}".format(str(self.pkt), self.nexthop, self.egress_dev, self.attempts, self.last_update, time.time())


class Router(object):
    '''
    A Router takes in packets and sends them out the correct port.
    
    :param Net net: the Switchyard Net object
    '''
    def __init__(self, net):
        self.net = net
        self.interfaces = {}         # Maps interface names to interface objects
        self.mymacs = set()          # Set of MAC addresses for all interfaces
        self.myips = set()           # Set of IP addresses for all interfaces
        self.arptable = {}           # Maps IP addresses to MAC addresses
        self.layer2_forward_list = []# Stores ArpPending objects
        self.forwarding_table = []   # Change this if you want to!

        for intf in net.interfaces():
            self.interfaces[intf.name] = intf
            self.mymacs.add(intf.ethaddr)
            for ipaddr in intf.ipaddrs:
                self.arptable[ipaddr] = intf.ethaddr
                self.myips.add(ipaddr)

        # *** You will need to add more code to this constructor ***
        print("Forwarding table:")
        self.forwarding_table = self.build_forwarding_table()

    #IPv4 address class is NOT part of switchyard!
    #python standard library for IP addresses

    # method sig.: layer2_forward(interface, ethernet address, packet, xtype=IP)
    def layer2_forward(self, intf, ethaddr, pkt, xtype=IPv4):

        if xtype == EtherType.ARP:
            pkt.prepend_header(Ethernet())
            pkt.get_header(Ethernet).dst = pkt.get_header(Arp).targethwaddr
            pkt.get_header(Ethernet).src = pkt.get_header(Arp).senderhwaddr
            pkt.get_header(Ethernet).ethertype = EtherType.ARP
            print(str(pkt))
        else: #IPv4
            # get MAC address and insert into Ethernet header
            # debugger()
            src_addr = None
            curr_ip = pkt.get_header(IPv4).dst
            for ipaddr in self.arptable:
                # https://stackoverflow.com/questions/40839147/ipaddress-module-valueerrors-has-host-bits-set-self
                ip_net = IPv4Network(ipaddr, False)
                if (curr_ip in ip_net) and curr_ip != ip_net:
                    src_addr = self.arptable[ipaddr]
                    break
            pkt.get_header(Ethernet).dst = ethaddr
            if src_addr:
                pkt.get_header(Ethernet).src = src_addr
            pkt.get_header(Ethernet).ethertype = EtherType.IPv4
            print(src_addr)
            print(ethaddr)

            # debugger()

        self.net.send_packet(intf, pkt) 

    def update_arp_table(self, ipaddr, macaddr):
        '''
        Associates the specified IP address with the specified MAC address 
        in the ARP table.
        '''
        log_info("Adding {} -> {} to ARP table".format(ipaddr, macaddr))
        self.arptable[ipaddr] = macaddr
        self.process_arp_pending()

    def arp_responder(self, dev, eth, arp):
        '''
        This is the part of the router that processes ARP requests and determines
        whether to update its ARP table and/or reply to the request
        '''
        # learn what we can from the arriving ARP packet
        if arp.senderprotoaddr != IPv4Address("0.0.0.0") and arp.senderhwaddr != EthAddr("ff:ff:ff:ff:ff:ff"):
            self.update_arp_table(arp.senderprotoaddr, arp.senderhwaddr)

        # if this is a request, reply if the targetprotoaddr is one of our addresses
        if arp.operation == ArpOperation.Request:
            log_debug("ARP request for {}".format(str(arp)))
            if arp.targetprotoaddr in self.myips: 
                log_debug("Got ARP for an IP address we know about")
                arpreply = create_ip_arp_reply(self.arptable[arp.targetprotoaddr], eth.src, arp.targetprotoaddr, arp.senderprotoaddr)
                self.update_arp_table(arp.sendpkt.payload.protosrc, pkt.payload.hwsrc)
                self.net.send_packet(dev, arpreply)

    def build_forwarding_table(self):
        file_contents = self.read_file()
        forwarding_table = {}
        for line in file_contents:
            net_addr = IPv4Network(f'{line[0]}/{line[1]}')
            forwarding_table[net_addr] = {'nexthop': IPv4Address(line[2]), 'intf': line[3]}
        for ipaddr, intf in zip(self.myips, self.interfaces):
            forwarding_table[ipaddr] = {'nexthop': None, 'intf': intf}

        for entry in forwarding_table:
            print('{}: {}'.format(entry, forwarding_table[entry]))

        return forwarding_table

    def read_file(self):
        with open('forwarding_table.txt', 'r') as f:
            lines = f.read().split('\n')
            file_contents = [line.split(' ') for line in lines]
        return file_contents
    
    def longest_prefix_match(self, destaddr):
        # TODO: implement this method
        matched_addr = None
        max_pref_len = sys.maxsize
        for net_addr in self.forwarding_table:
            nexthop = self.forwarding_table[net_addr]['nexthop']
            prefix = IPv4Address(str(net_addr).split('/')[0]) 
            destaddr = IPv4Address(destaddr)
            print("destaddr: " + str(destaddr))
            print("prefix: " + str(prefix))
            print("nexthop: " + str(nexthop))
            matches_net = destaddr in IPv4Network(net_addr, False)
            if nexthop:
                matches_nexthop = destaddr in IPv4Network(nexthop, False)
                if matches_nexthop and (abs((int(nexthop)-int(destaddr))) < max_pref_len):
                    max_pref_len = int(destaddr)-int(nexthop)
                    matched_addr = nexthop

            if matches_net and (abs((int(prefix)-int(destaddr))) < max_pref_len):
                max_pref_len = int(destaddr)-int(prefix)
                matched_addr = IPv4Address(str(net_addr).split('/')[0])
        return matched_addr

    def router_main(self):    
        while True:
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)

            except NoPackets:
                log_debug("Timeout waiting for packets")
                continue

            except Shutdown:
                return

            eth = pkt.get_header(Ethernet)

            # if destination is the router, drop
            # if pkt.get_header(Ethernet).dst in [port.ethaddr for port in self.net.ports()]:
            #     continue

            if eth.ethertype == EtherType.ARP:
                log_debug("Received ARP packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                self.arp_responder(dev, eth, arp)

            elif eth.ethertype == EtherType.IP:
                log_debug("Received IP packet: {}".format(str(pkt)))
                # TODO: process the IP packet and send out the correct interface
                destaddr = pkt.get_header(IPv4).dst
                matched_addr = self.longest_prefix_match(destaddr)
                if matched_addr:
                    pkt.get_header(IPv4).ttl -= 1 # decrement time to live of IP header

                    port = 'router-eth0'
                    for key in self.forwarding_table.keys():
                        entry = self.forwarding_table[key]
                        if key == matched_addr or entry['nexthop'] == matched_addr:
                            port = entry['intf']

                    print("curr_ip: {} {}".format(matched_addr, port))
                    arp_pending = ArpPending(port, matched_addr, pkt)
                    # arp_pending = ArpPending(matched_addr, destaddr, pkt)
                    self.layer2_forward_list.append(arp_pending)
                    self.process_arp_pending()
            else:
                log_warn("Received Non-IP packet that I don't know how to handle: {}".format(str(pkt)))
            # debugger()

    def process_arp_pending(self):
        '''
        Once an ArpPending object has been added to the layer 2 forwarding table, 
        this method handles the logistics of determining whether an ARP request 
        needs to be sent at all, and if so, handles the logistics of sending and 
        potentially resending the request.
        '''
        def _ipv4addr(intf):
            v4addrs = [i.ip for i in intf.ipaddrs if i.version == 4]
            return v4addrs[0]

        i = 0
        now = time.time()
        log_info("Processing outstanding packets to be ARPed at {}".format(now))
        newlist = []
        while len(self.layer2_forward_list):
            thisarp = self.layer2_forward_list.pop(0)
            log_debug("Checking {}".format(str(thisarp)))
            log_debug("Current arp table: {}".format(str(self.arptable)))

            dstmac = None
            # Check: do we already know the MAC address? If so, go ahead and forward 
            log_debug(thisarp.nexthop)
            if thisarp.nexthop in self.arptable:
                dstmac = self.arptable[thisarp.nexthop]
                log_info("Already have MAC address for {}->{} - don't need to ARP".format(thisarp.nexthop, dstmac))
                # **NOTE: you will need to provide an implementation of layer2_forward
                self.layer2_forward(thisarp.egress_dev, dstmac, thisarp.pkt)
            else:
                # Not in ARP table, so send ARP request if we haven't timed out.
                if thisarp.can_try_again(now):
                    arpreq = self.make_arp_request(self.interfaces[thisarp.egress_dev].ethaddr, _ipv4addr(self.interfaces[thisarp.egress_dev]), thisarp.nexthop)
                    p = Packet()
                    p += arpreq
                    log_info("ARPing for {} ({})".format(thisarp.nexthop, arpreq))
                    thisarp.add_attempt()

                    # **NOTE: you will need to provide an implementation of layer2_forward
                    self.layer2_forward(thisarp.egress_dev, "ff:ff:ff:ff:ff:ff",
                                        p, xtype=EtherType.ARP)
                    newlist.append(thisarp)
                elif thisarp.giveup(now):
                    log_warn("Giving up on ARPing {}".format(str(thisarp.nexthop)))

        self.layer2_forward_list = newlist

    def make_arp_request(self, hwsrc, ipsrc, ipdst):
        arp_req = Arp()
        arp_req.operation = ArpOperation.Request
        arp_req.senderprotoaddr = IPv4Address(ipsrc)
        arp_req.targetprotoaddr = IPv4Address(ipdst)
        arp_req.senderhwaddr = EthAddr(hwsrc)
        arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
        return arp_req


def main(net):
    '''
    Main entry point for router.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
