#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket, struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    ICMP = 1
    TCP = 6
    UDP = 17
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []
        rules = open('rules.conf')
        for line in rules:
            if line[0] != '%' and line != '\n':
                line = line.split(' ')
                self.rules.append(tuple(line)) # line has format: (<verdict>, <protocol>, <external IP address>, <external port>) 
                                               # or (<verdict>, dns, <domain name>)
        self.ip_DB = []
        ip_ranges = open('geoipdb.txt')
        for line in ip_ranges:
            line_array = line.split(' ') 
            line_array[0] = self.ip2long(line_array[0]) # Go from IP string to decimal: '1.0.0.0' => 16777216. 
            line_array[1] = self.ip2long(line_array[1])
            line_array[2] = line_array[2].replace('\n', '') #strip new line character from country string
            self.ip_DB.append(tuple(line_array)) #line_array = [start_ip (decimal), end_ip (decimal), country]
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        #drop packet if header length is < 5 (spec)
        header_len = (ord(pkt[0:1]) & 0x0f) * 4
        ip_header = pkt[0: header_len]
        transport_header = pkt[header_len: -1]
        protocol = ord(ip_header[9:10])

        external_ip = ip_header[12:16] # initialize external_ip to source ip (where packet came from)
        external_port = transport_header[0:2]
        if pkt_dir == PKT_DIR_OUTGOING:
            external_ip = ip_header[16: 20] #overwrite external_ip to destination ip if packet is outgoing FLAG: is this right?
            external_port = transport_header[0:2]
        external_ip = self.ip2long(socket.inet_ntoa(external_ip)) #go from bytes to ip string to long.
    
        #an ICMP packet does not have an external_port.
        if protocol == ICMP:
            icmp_type = transport_header[0:1]
        pass

    # TODO: You can add more methods as you want.
    @staticmethod
    def ip2long(ip):
        """
        Convert an IP string to long
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    @staticmethod
    def db_search(ip, db, min, max):
        """
        Given an ip address and a db return the entry that
        contains ip in its range. If no such entry exists return
        None.
        """
        mid = (min_val + max_val) / 2
        if ip < ip_DB[mid][0]:
            return db_search(ip, db, min_val, mid - 1)
        else if ip > ip_DB[search_range / 2][1]:
            return db_search(ip, db, mid + 1, max_val)
        else:
            return ip_DB[mid]


# TODO: You may want to add more classes/functions as well.
