#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket, struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []
        rules = open('rules.conf')
        for line in rules:
            if line[0] != '%' and line != '\n':
                self.rules.append(line)
        # print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
        #         config['rule']

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.ip_DB = []
        ip_ranges = open('geoipdb.txt')
        for line in ip_ranges:
            line_array = line.split(' ') 
            line_array[0] = self.ip2long(line_array[0]) # Go from IP string to decimal: '1.0.0.0' => 8. 
            line_array[1] = self.ip2long(line_array[1])
            line_array[2] = line_array[2].replace('\n', '') #strip new line character from country string
            self.ip_DB.append(tuple(line_array)) #line_array = [start_ip (decimal), end_ip (decimal), country]
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
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
