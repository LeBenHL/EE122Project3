#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket, struct
from bisect import bisect_left
from datetime import datetime
import random

# TODO: Feel free to import any Python standard modules as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
class MalformedPacketException(Exception):
  pass

class Firewall:

    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.traceroute_sources = {1: "192.168.122.1", 2: "192.168.122.2", 3: "192.168.122.122"}

        try:
            self.lossy = True
            self.loss_percentage = float(config['loss'])
        except KeyError:
            self.lossy = False

        parser = RulesParser(config['rule'])
        self.rules = parser.parse_rules()

        # TODO: Also do some initialization if needed.

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):

        # TODO: need to add support for log http <host name>
        #Lossy Firewall
        if (self.lossy and self.loss_percentage > random.uniform(0, 100)):
          pass
        else:
          #TODO Try Catch 
          try:
            protocol, ext_IP_address, ext_port, check_dns_rules, domain_name = self.read_packet(pkt, pkt_dir)
            wrapped_packet = WrappedPacket(protocol, ext_IP_address, ext_port, check_dns_rules, domain_name)

            verdict = self.packet_lookup(wrapped_packet)

            if pkt_dir == PKT_DIR_INCOMING:
              #print "Incoming Verdict: %s, Protocol: %s, ext_IP_address: %s, ext_port: %s, domain_name: %s" % (verdict, protocol, ext_IP_address, ext_port, domain_name)
              pass
            else:
              #print "Outgoing Verdict: %s, Protocol: %s, ext_IP_address: %s, ext_port: %s, domain_name: %s" % (verdict, protocol, ext_IP_address, ext_port, domain_name)
              pass

            if verdict == "pass":
              if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
              else: # pkt_dir == PKT_DIR_OUTGOING
                #TRACEROUTE 192.168.122.122!
                if protocol == "udp" and ext_IP_address == "192.168.122.122":
                  self.respond_to_traceroute(pkt)
                else:
                  self.iface_ext.send_ip_packet(pkt)
            elif verdict == "deny":
              if protocol == "tcp":
                self.handle_deny_tcp(ext_IP_address, port)
              else:
                self.handle_deny_dns(domain_name, pkt)
            elif verdict == "log":
              pass
            elif verdict == "drop":
              #Do Nothing to just drop it
              pass
          except IndexError as e:
            pass
            print e
          except MalformedPacketException as e:
            pass

    def respond_to_traceroute(self, pkt):
      #GET TTL Value
      TTL = struct.unpack("!B", pkt[8:9])[0]
      source = self.traceroute_sources[TTL]
      ip_section, transport_section, app_section = self.split_by_layers(pkt)

      if False:
        TYPE = chr(0)
        CODE = chr(0)

        IDENTIFIER = struct.pack("!H", 0)
        SEQ_NO = struct.pack("!H", 0)

        CHECKSUM = self.calculate_checksum(self.calculate_sum(TYPE + CODE + IDENTIFIER + SEQ_NO))

        ICMP_DATA = TYPE + CODE + CHECKSUM + IDENTIFIER + SEQ_NO

      else:
        TYPE = chr(11)
        CODE = chr(0)

        UNUSED = struct.pack("!L", 0)

        IP_HEADER_PLUS_DATA = ip_section + transport_section[:8]

        CHECKSUM = self.calculate_checksum(self.calculate_sum(TYPE + CODE + UNUSED + IP_HEADER_PLUS_DATA))

        ICMP_DATA = TYPE + CODE + CHECKSUM + UNUSED + IP_HEADER_PLUS_DATA

      IP_HEADER = self.generate_IP_header(ip_section, ICMP_DATA, source=socket.inet_aton(source), protocol=chr(1))

      self.iface_int.send_ip_packet(IP_HEADER + ICMP_DATA)

    def handle_deny_tcp(self, ext_IP_address, port):
      pass


    def handle_deny_dns(self, domain_name, pkt):
      ip_section, transport_section, app_section = self.split_by_layers(pkt)

      #Generate DNS response from the app_section data
      app_data = self.generate_DNS_response(app_section, domain_name)

      #Generate UDP header from the transport_section data and the app data
      transport_header = self.generate_UDP_header(ip_section, transport_section, app_data)

      #Generate IP header from the ip_section and payload
      ip_header = self.generate_IP_header(ip_section, transport_header + app_data)

      #Send the Constructed Packet to INT Interface
      self.iface_int.send_ip_packet(ip_header + transport_header + app_data)

    def split_by_layers(self, pkt):
      #Splits a packet into its relevant IP, Transport, and APP Layer Sections
      header_len_tmp = struct.unpack('!B',pkt[0])[0]
      header_len = header_len_tmp & 0x0F
      if header_len < 5:
        # Check additional specs to see that packets with header length < 5 should be dropped.
        raise MalformedPacketException("Header Length Less than 5")
      else: # header_len >= 5
        tl_index = header_len*4

      #Need to retrieve the protocol that the packet follows to find AL Index
      protocol_tmp = struct.unpack('!B',pkt[9])[0] # Protocol number corresponding to TCP/UDP/ICMP-type

      if protocol_tmp == 1:
        #icmp
        al_index = tl_index + 8
      elif protocol_tmp == 6:
        #TCP
        tcp_header_len_tmp = struct.unpack('!B',pkt[tl_index + 12])[0]
        tcp_header_len = (header_len_tmp & 0xF0) >> 4
        al_index = tcp_header_len * 4
      elif protocol_tmp == 17:
        #UDP
        al_index = tl_index + 8

      return (pkt[:tl_index], pkt[tl_index:al_index], pkt[al_index:])

    def generate_DNS_response(self, app_section, domain_name):
      #Generates a DNS response to the question

      #Generate Header
      ID = app_section[0:2]
      QR_TO_RCODE = struct.pack('!H', 0b1000000000000000)
      QDCOUNT = struct.pack('!H', 0)
      ANCOUNT = struct.pack('!H', 1)
      NSCOUNT = struct.pack('!H', 0)
      ARCOUNT = struct.pack('!H', 0)

      HEADER = ID + QR_TO_RCODE + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

      #Generate Answer Section
      NAME = ""
      list_of_domain_parts = domain_name.split('.')
      for domain_part in list_of_domain_parts: 
        NAME += chr(len(domain_part)) + bytes(domain_part)
      NAME += chr(0)

      TYPE = struct.pack("!H", 0x0001)
      CLASS = struct.pack("!H", 0x0001)
      TTL = struct.pack("!L", 0x00000001)
      RDATA = socket.inet_aton("169.229.49.109")
      RDLENGTH = struct.pack('!H', len(RDATA))

      ANSWER = NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA

      return HEADER + ANSWER

    def generate_UDP_header(self, ip_section, transport_section, app_data):
      #Reverse Src/Dest from original transport section
      #Checksum pseudocode from http://www.bloof.de/tcp_checksumming
      SOURCE_PORT = transport_section[2:4]
      DESTINATION_PORT = transport_section[0:2]

      LENGTH = struct.pack('!H', 8 + len(app_data))

      summation = self.calculate_sum(SOURCE_PORT + DESTINATION_PORT + LENGTH + app_data)

      #Add Psuedo Header to Summation
      summation += struct.unpack('!H', ip_section[12:14])[0] 
      summation += struct.unpack('!H', ip_section[14:16])[0] 
      summation += struct.unpack('!H', ip_section[16:18])[0] 
      summation += struct.unpack('!H', ip_section[18:20])[0] 
      summation += 8 + len(app_data)
      summation += 17

      CHECKSUM = self.calculate_checksum(summation)

      return SOURCE_PORT + DESTINATION_PORT + LENGTH + CHECKSUM

    def calculate_sum(self, data):
      #Calculates a sum from the given data to be used in a checksum later
      #Pseudo Code from http://www.bloof.de/tcp_checksumming
      summation = 0
      bytes_left = len(data)
      index = 0

      while bytes_left > 1:
        summation += struct.unpack('!H', data[index:index+2])[0]
        bytes_left -= 2
        index += 2

      if bytes_left > 1:
        summation += struck.unpack('!B', data[index:index+1])[0] << 8

      return summation

    def calculate_checksum(self, summation):
      #Calculates a checksum from the given summation
      #Pseudo Code from http://www.bloof.de/tcp_checksumming
      summation = (summation >> 16) + (summation & 0xFFFF)

      return struct.pack('!H', ~summation & 0xFFFF)

    def generate_IP_header(self, ip_section, payload, source=None, dest=None, protocol=None):
      #Generate an return IP header by taking the original ip header minus options and updating the
      #IP Header Length, Total Length, Checksum, Src and Dest Fields
     
      VERSION_AND_HEADER_LENGTH = chr((4 << 4) + 5)
      TOS = chr(0)
      TOTAL_LENGTH = struct.pack('!H', len(payload) + 20)
      IDENTIFICATION_TO_TTL = ip_section[4:9]

      if protocol is None:
        PROTOCOL = ip_section[10]
      else:
        PROTOCOL = protocol

      #Reverse Source and Destination if source or dest not specificed
      if source is None:
        SOURCE = ip_section[16:20]
      else:
        SOURCE = source

      if dest is None:
        DEST = ip_section[12:16]
      else:
        DEST = dest

      summation = self.calculate_sum(VERSION_AND_HEADER_LENGTH + TOS + TOTAL_LENGTH + IDENTIFICATION_TO_TTL + PROTOCOL + SOURCE + DEST)

      CHECKSUM = self.calculate_checksum(summation)

      return VERSION_AND_HEADER_LENGTH + TOS + TOTAL_LENGTH + IDENTIFICATION_TO_TTL + PROTOCOL + CHECKSUM + SOURCE + DEST

    # Acts as a parser for the packet
    # Returns the protocol, external IP address, and the external port associated with the packet
    # Also determines whether or not a packet is a DNS packet and returns that as well
    # TODO: Check that packets are laid out in memory BIG-ENDIAN
    def read_packet(self, pkt, pkt_dir):

      # Need to retrieve the protocol that the packet follows
      protocol_tmp = struct.unpack('!B',pkt[9])[0] # Protocol number corresponding to TCP/UDP/ICMP-type
      if protocol_tmp == 1:
        protocol = "icmp"
      elif protocol_tmp == 6:
        protocol = "tcp"
      elif protocol_tmp == 17:
        protocol = "udp"
      else:
        #Not a Protocol we recognize, should we just drop?
        return (None, None, None, None, None)

      header_len_tmp = struct.unpack('!B',pkt[0])[0]
      header_len = header_len_tmp & 0x0F
      if header_len < 5:
        # Check additional specs to see that packets with header length < 5 should be dropped.
        raise MalformedPacketException("Header Length Less than 5")
      else: # header_len >= 5
        tl_index = header_len*4

      if pkt_dir == PKT_DIR_INCOMING:
        ext_ip_tmp = pkt[12:16] # external IP address is source IP address
        if protocol == "tcp" or protocol =="udp":
          ext_port = struct.unpack('!H',pkt[tl_index:tl_index+2])[0]
        # Retrieve the source IP address and source port of the packet
      else: # pkt_dir == PKT_DIR_OUTGOING
        ext_ip_tmp = pkt[16:20] # external IP address is destination IP address
        if protocol == "tcp" or protocol == "udp":
          ext_port = struct.unpack('!H',pkt[tl_index+2:tl_index+4])[0]

      # Packet is ICMP-type packet
      if protocol == "icmp":
        ext_port = struct.unpack('!B',pkt[tl_index])[0] # Independent of pkt_dir value

      # Retrieve the string representation of the external IP address of a packet
      ext_IP_address = socket.inet_ntoa(ext_ip_tmp)

      # check_dns_rules determines whether or not a packet should be considered
      # for DNS rule matching. Initially set to False unless can prove otherwise.
      check_dns_rules = False
      domain_name = None

      if pkt_dir == PKT_DIR_OUTGOING and protocol == "udp" and ext_port == 53:
        # Check to see if there is exactly one DNS question entry
        # Application layer starts at index = tl_index + 8 for UDP
        al_index = tl_index + 8
        QDCOUNT = struct.unpack('!H',pkt[al_index+4:al_index+6])[0]
        if QDCOUNT == 1:
          len_byte_index = al_index+12
          length_byte = struct.unpack('!B',pkt[len_byte_index])[0]
          list_of_domain_parts = []
          while length_byte != 0:
            list_of_ascii_char = []
            ascii_chars = pkt[len_byte_index+1:len_byte_index+1+length_byte]
            for ascii_char in ascii_chars:
              list_of_ascii_char.append(struct.unpack('!B', ascii_char)[0])
            list_of_domain_parts.append(list_of_ascii_char)
            len_byte_index = len_byte_index+length_byte+1
            length_byte = struct.unpack('!B', pkt[len_byte_index])[0]

          len_byte_index += 1

          # Converts the list list_of_domain_parts to a string domain name
          domain_name = self.parse_domain_name(list_of_domain_parts).lower()

          # len_byte_index now represents the starting index of QTYPE
          QTYPE = struct.unpack('!H',pkt[len_byte_index:len_byte_index+2])[0]
          QCLASS = struct.unpack('!H',pkt[len_byte_index+2:len_byte_index+4])[0]
          if (QTYPE == 1 or QTYPE == 28) and QCLASS == 1:
            check_dns_rules = True

      return protocol, ext_IP_address, ext_port, check_dns_rules, domain_name

    # Given a list
    # [(0x77, 0x77, 0x77), (0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65), (0x63, 0x6f, 0x6d)]
    # return "www.google.com"
    def parse_domain_name(self, list_of_domain_parts):
      domain_parts = []
      for domain_part in list_of_domain_parts:
        domain_parts.append(bytearray(domain_part).decode('ascii').encode('ascii'))
      return ".".join(domain_parts)


    # Looks through the self.rules list and returns the verdict of the latest
    # rule in the list that matches the packet fields
    # Returns verdict==True if no rules in the list match the packet fields
    def packet_lookup(self, wrapped_packet):

      # Set verdict initially to true so that if no rules match packet fields
      # then the packet will be passed to the appropriate interface
      verdict = "pass"

      for rule in self.rules:
        if rule.protocol == wrapped_packet.protocol:
          # Examine rule further since rule protocol matches packet protocol (TCP/UDP/ICMP)
          if wrapped_packet.ext_IP_address == rule.ext_IP_address and wrapped_packet.ext_port == rule.ext_port:
            verdict = rule.verdict
        elif rule.protocol == "dns" and wrapped_packet.check_dns_rules:
          # Examine rule further since check_dns_rules indicates that a packet should be checked against DNS rules
          # wrapped_packet only has a domain_name field if check_dns_rules is true for wrapped_packet
          if wrapped_packet.domain_name == rule.domain_name:
            verdict = rule.verdict
      return verdict

    # TODO: You can add more methods as you want.

class RulesParser:

  def __init__(self, filename):
    self.filename = filename

  def parse_rules(self):
    f = open(self.filename, 'r')
    rules = []
    for line in f:
      line = line.strip()
      #Ignore All lines that are blank or comment lines
      if line and not self._is_comment_line(line):
        rule = self.parse_line(line)
        if rule:
          rules.append(rule)
    return rules

  def parse_line(self, line):
    tokens = line.split()
    #Make all tokens lowercase so we ignore case sensitivity
    tokens = map(lambda token: token.lower(), tokens)

    #Rules that have 4 fields are normal rules
    if len(tokens) == 4:
      return Rule(*tokens)
    #DNS Rules
    elif len(tokens) == 3:
      return DNSRule(*tokens)
    else:
      return None

  def _is_comment_line(self, line):
    return line.startswith("%")

class GeoDBParser:

  def __init__(self, filename):
    self.filename = filename

  def parse_lines(self):
    f = open(self.filename, 'r')
    nodes = []
    for line in f:
      node = self.parse_line(line)
      if node:
        nodes.append(node)
    return nodes

  def parse_line(self, line):
    tokens = line.split()
    #Make all tokens lowercase so we ignore case sensitivity
    tokens = map(lambda token: token.lower(), tokens)

    #GeoDB lines should have 3 fields
    if len(tokens) == 3:
      return GeoDBNode(*tokens)
    else:
      return None

class GeoDBNode:

  def __init__(self, start_ip, end_ip, country_code):
    self.start_ip = self.ip_to_int(start_ip)
    self.end_ip = self.ip_to_int(end_ip)
    self.country_code = country_code

  def __lt__(self, other):
    ip = self.ip_to_int(other)
    return self.end_ip < ip

  def __le__(self, other):
    return self.__lt__(other) or self.__eq__(other)

  def __ne__(self, other):
    return not self.__eq__(other)

  def __eq__(self, other):
    ip = self.ip_to_int(other)
    return self.start_ip <= ip and ip <= self.end_ip

  def __gt__(self, other):
    ip = self.ip_to_int(other)
    return self.start_ip > ip

  def __ge__(self, other):
    return self.__gt__(other) or self.__eq__(other)

  def ip_to_int(self, ip):
    #From http://gist/githib.com/cslarsen/1595135
    return reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))

class Rule:

  def __init__(self, verdict, protocol, ext_IP_address, ext_port):
    self.verdict = verdict
    self.protocol = protocol
    self.ext_IP_address = IPAddressField(ext_IP_address)
    self.ext_port = ExtPortField(ext_port)

class WrappedPacket:

  def __init__(self, protocol, ext_IP_address, ext_port, check_dns_rules, domain_name):
    self.protocol = protocol
    self.ext_IP_address = IPAddressField(ext_IP_address)
    self.ext_port = ExtPortField(ext_port)
    self.check_dns_rules = check_dns_rules
    if self.check_dns_rules:
      self.domain_name = DomainNameField(domain_name)

class DNSRule(Rule):

  def __init__(self, verdict, protocol, domain_name):
    self.verdict = verdict
    self.protocol = protocol
    self.domain_name = DomainNameField(domain_name)

class IPAddressField:

  geoParser = GeoDBParser('geoipdb.txt')
  geo_nodes = geoParser.parse_lines()

  def __init__(self, ext_IP_address):
    self.ext_IP_address = ext_IP_address

    # Have this set up as a field so that way don't have to
    # keep determining if IPAddressField obj wraps an IP prefix
    if "/" in self.ext_IP_address:
      self.is_IP_prefix = True
      # Element 0 is the IP, Element 1 is the slash #
      _decimal_ip_and_prefix = self.ext_IP_address.split("/")
      # Ask: any reason to make ip_to_int an instance function?
      self._decimal_ip = self.ip_to_int(_decimal_ip_and_prefix[0])
      self.slash_num = int(_decimal_ip_and_prefix[1])
      self.relevant_portion = self.relevant_ip_portion(self._decimal_ip, self.slash_num)
    else:
      self.is_IP_prefix = False


  # Assume that the lhs of "==" is always the external IP address
  # of the packet, while the rhs is always the external Ip addr of the
  # rule that you're trying to match up with the packet
  def __eq__(self, other):
    if other.ext_IP_address == "any":
      return True
    elif len(other.ext_IP_address) == 2:
      # other.ext_IP_address is a 2-byte country code
      return self.belongs_to_country(self.ext_IP_address, other.ext_IP_address)
    elif other.is_IP_prefix:
      decimal_ip = self.ip_to_int(self.ext_IP_address)
      return self.relevant_ip_portion(decimal_ip, other.slash_num) == other.relevant_portion
    else:
      # other.ext_IP_address is just an IP address
      return self.ip_to_int(self.ext_IP_address) == self.ip_to_int(other.ext_IP_address)

  #Returns True if the given ip belongs to a certain country. False o/w
  def belongs_to_country(self, ip, country_code):
    geo_node = self._bin_search(ip)
    if geo_node:
      return geo_node.country_code == country_code
    else:
      return False

  #Finds the GeoDBNode within the range of the given IP or None if no node of appropriate range is found
  def _bin_search(self, ip):
    i = bisect_left(self.geo_nodes, ip)
    if i != len(self.geo_nodes):
      node = self.geo_nodes[i]
      if node == ip:
        return node
      else:
        return None
    else:
      return None

  def ip_to_int(self, ip):
    #From http://gist/githib.com/cslarsen/1595135
    return reduce(lambda a,b: a<<8 | b, map(int, ip.split(".")))

  # Return the network component of the inputted IP address zero-extended
  # at the end (for later comparison of network component portions)
  def relevant_ip_portion(self, ip, slash_num):
    subnet_mask = 0xFFFFFFFF >> (32 - slash_num)
    subnet_mask = subnet_mask << (32 - slash_num)
    relevant_ip = ip & subnet_mask
    return relevant_ip


class ExtPortField:

  def __init__(self, ext_port):
    if self.is_integer(ext_port):
      self.ext_port = int(ext_port)
      self.is_a_range = False
    else:
      self.ext_port = ext_port
      self.is_a_range = False
      if "-" in self.ext_port:
        self.is_a_range = True
        self._temp_list = self.ext_port.split("-")
        self.start_port = int(self._temp_list[0])
        self.end_port = int(self._temp_list[1])

  # Assume that the lhs of "==" is always the external port
  # of the packet, while the rhs is always the external port of the
  # rule that you're trying to match up with the packet
  def __eq__(self, other):
    if other.ext_port == "any":
      return True
    elif other.is_a_range:
      return self.ext_port >= other.start_port and self.ext_port <= other.end_port
    else:
      # other.ext_port should be a single value
      return self.ext_port == other.ext_port

  def is_integer(self, val):
    try:
      int(val)
      return True
    except ValueError:
      return False


class DomainNameField:

  def __init__(self, domain_name):
    self._domain_name = domain_name
    self.rev_domain_name_list = self._domain_name.split(".")
    # self.rev_domain_name_list is the result of a string split into
    # multiple elements by the . delimiter, followed by a reverse oper.
    # that reverses the elements in the list
    self.rev_domain_name_list.reverse()

  # Assume that the lhs of "==" is always the domain name
  # of the packet, while the rhs is always the domain name of
  # the rule that you're trying to match up with the packet
  def __eq__(self, other):
    for i, partURL in enumerate(other.rev_domain_name_list):
      # Assume that DNS query rules only have good syntax
      if partURL == "*":
        # Since the current partURL is "*", do not care what the rest of self.rev_domain_name_list is
        return True
      else:
        # partURL is a portion of a url like "gov" or "fda"
        if partURL != self.rev_domain_name_list[i]:
          return False

    return len(self.rev_domain_name_list) == len(other.rev_domain_name_list)

# TODO: You may want to add more classes/functions as well.
