#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket, struct
from bisect import bisect_left
from datetime import datetime

# TODO: Feel free to import any Python standard modules as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        parser = RulesParser(config['rule'])
        self.rules = parser.parse_rules()

        # TODO: Also do some initialization if needed.

    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.

        protocol, ext_IP_address, ext_port, is_dns_pkt = self.read_packet(pkt, pkt_dir)

        list_of_rules = self.packet_lookup(protocol, ext_IP_address, ext_port, is_dns_pkt)

        if verdict == "pass":
          if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
          else: # pkt_dir == PKT_DIR_OUTGOING
            self.iface_ext.send_ip_packet(pkt)

    # Acts as a parser for the packet
    # Returns the protocol, external IP address, and the external port associated with the packet
    # Also determines whether or not a packet is a DNS packet and returns that as well
    def read_packet(self, pkt, pkt_dir):
      # Need to retrieve the protocol that the packet follows
      
      if pkt_dir == PKT_DIR_INCOMING:
        pass
        # Retrieve the source IP address and source port of the packet
      else: # pkt_dir == PKT_DIR_OUTGOING
        pass
        # Retrieve the destination IP address and destination port of the packet

      # Determine whether or not the packet is a DNS query

      return protocol, ext_IP_address, ext_port, is_dns_pkt

    # Searches through the rules file given as input in a linear fashion
    # and appends rules(as named tuples) to the list list_of_rules in the
    # order that they match the packet criteria
    def packet_lookup(self, protocol, ext_IP_address, ext_port, is_dns_pkt):
      pass

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

class DNSRule(Rule):

  def __init__(self, verdict, protocol, domain_name):
    self.verdict = verdict
    self.protocol = protocol
    self.domain_name = DomainNameField(domain_name)

class IPAddressField:

  geoParser = GeoDBParser('geoipdb.txt')
  geo_nodes = geoParser.parse_lines()

  def __init__(self, ext_IP_address):
    pass

  def __eq__(self, other):
    pass

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

class ExtPortField:

  def __init__(self, ext_port):
    pass

  def __eq__(self, other):
    pass

  def _is_integer(self, ext_port):
    try:
      int(ext_port)
      return True
    except ValueError:
      return False

class DomainNameField:

  def __init__(self, domain_name):
    pass

  def __eq__(self, other):
    pass

# TODO: You may want to add more classes/functions as well.
