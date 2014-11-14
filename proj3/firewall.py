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
        header_len = (ord(pkt[0:1]) & 0x0f) * 4
        #drop packet if header length is < 5 (spec)
        if header_len < 5:
            return
        ip_header = pkt[0: header_len]
        transport_header = pkt[header_len:]
        protocol = ord(ip_header[9:10])
        
        if pkt_dir == PKT_DIR_OUTGOING:
            external_ip = ip_header[16: 20] 
            external_port = struct.unpack('!H', transport_header[2:4])[0]
        #packet is incoming
        else:
            external_ip = ip_header[12:16] # initialize external_ip to source ip (where packet came from)
            external_port = struct.unpack('!H', transport_header[0:2])

        external_ip = socket.inet_ntoa(external_ip) #go from bytes to ip string
        
        #an ICMP packet does not have an external_port.
        if protocol == Firewall.ICMP:
            icmp_type = transport_header[0:1]

        #figure out what type of packet we have.
        is_dns_packet = False
        
        #handle dns parsing
        if external_port == 53 and protocol == Firewall.UDP:
            #FLAG The project specs mentions that we are should be "primarily interested" in A and AAAA QTYPE packets. 
            #So does that mean that we drop packets that have a different QTYPE, or do we assume that they do not match any DNS rule? answ: the latter
            is_dns_packet = True #we know we have a DNS packet.    
            dns_header = transport_header[8:]
            qd_count = struct.unpack('!H', dns_header[4:6])[0]
            if qd_count > 1:
                return
            dns_question = dns_header[12:] #question portion of dns header
            qtype = struct.unpack('!H', dns_question[6:8])
            print('qtype is: ' + str(qtype))
            qname = self.get_domain_name(dns_question) #domain name (e.g. 'www.google.com')

        #handle packet rule matching.
        curr_match = None
        for rule in self.rules:
            #we have a Protocol/IP/Port Rule. These rules can be applied to all packets.
            if len(rule) == 4:
                if protocol == rule[1] and self.external_ip_matches(external_ip, rule[2]) and self.external_port_matches(external_port, rule[3]):
                    curr_match = rule

            # we have DNS rule
            else:
                #only check DNS rules if packet is a dns packet
                if is_dns_packet and self.domain_matches(qname, rule[2]):
                    curr_match = rule
        
        #send packet only if the last rule it matched says to let it pass
        if curr_match == None or curr_match[0] == 'pass':
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)

    # TODO: You can add more methods as you want.
    @staticmethod
    def external_ip_matches(external_ip, rule_ip):
        if rule_ip == 'any':
            return True
        #rule_ip is a 2 byte country code (e.g. 'it')
        elif len(rule_ip) == 2:
            external_ip = self.ip2long(external_ip) #go from bytes to ip string to long.
            db_entry = db_search(external_ip, self.ip_DB, 0, len(self.ip_DB) - 1)
            return db_entry[2] == rule_ip
        #FLAG we have cidr notation
        elif '/' in rule_ip:
            sig_bits = rule_ip[-1] # get thing after the slash (number of bits we have to look at)
            rule_ip = rule_ip[0: rule_ip.index('/')] #isolate ip address
            rule_ip_as_num = self.ip2long(rule_ip)
            rule_ip_as_bin = '{0:032b}'.format(ip_as_num) #go from num to binary string
            external_ip_as_num = self.ip2long(external_ip)
            external_ip_as_bin = '{0:032b}'.format(external_ip_as_num)
            return rule_ip_as_bin[0:sig_bits] == external_ip_as_bin[0:sig_bits]
        #regular ip
        else:
            return external_ip == rule_ip

    @staticmethod
    def external_port_matches(external_port, rule_port):
        if "-" not in rule_port:
            return external_port == int(rule_port)
        port_range = rule_port.split('-')
        return external_port >= int(port_range[0]) and external port <= int(port_range[1])

    @staticmethod
    def domain_matches(domain, rule_domain):
        if rule_domain == "*":
            return True
        elif rule_domain[0] == "*":
            for i in range(1, len(rule_domain)):
                if rule_domain[-i] != domain[-i]:
                    return False
            return True
        else:
            return domain == rule_domain

    @staticmethod
    def get_domain_name(qname):
        length_byte = struct.unpack('!b', qname[0:1])[0]
        curr_byte = 1
        domain_str = ''
        while length_byte != 0:
            for i in range(0, length_byte):
                domain_str += chr(struct.unpack('!B', qname[curr_byte:(curr_byte + 1)])[0])
                curr_byte += 1
            domain_str += '.'
            length_byte = struct.unpack('!b', qname[curr_byte:(curr_byte + 1)])[0]
            curr_byte += 1
        return domain_str

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
        if min > max:
            return None
        elif ip < ip_DB[mid][0]:
            return db_search(ip, db, min_val, mid - 1)
        elif ip > ip_DB[search_range / 2][1]:
            return db_search(ip, db, mid + 1, max_val)
        else:
            return ip_DB[mid]
