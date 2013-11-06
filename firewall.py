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
          if rule.protocol != "dns":
            rule.ext_IP_address == "128.0.0.1"
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
    self.ext_IP_address = ext_IP_address
    #Format "Any"
    if ext_IP_address == "any":
      self.type = "any"
    #Format Country Code
    elif len(ext_IP_address) == 2:
      self.type = "country code"
    #Hacky but this tells us if its a prefix
    elif "/" in ext_IP_address:
      self.type = "prefix"
    #Hacky but since we assume correct rules syntax, it is a normal IP address otherwise
    else:
      self.type = "ip address"

  def __eq__(self, other):
    if self.type == "any":
      return True
    elif self.type == "country code":
      return self.belongs_to_country(other, self.ext_IP_address)
    elif self.type == "prefix":
      tokens = self.ext_IP_address.split("/")
      prefix = tokens[0]
      slash = int(tokens[1])
      mask = int("1" * slash, 2) << (32 - slash)
      return (self.ip_to_int(prefix) & mask) == (self.ip_to_int(other) & mask)
    elif self.type == "ip address":
      return other == self.ext_IP_address
    else:
      raise Exception("WTF")

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
    self.ext_port = ext_port
    #Format "Any"
    if ext_port == "any":
      self.type = "any"
    #Format Single Number
    elif self._is_integer(ext_port):
      self.type = "number"
    #Format Range
    else:
      self.type = "range"
      self.range = reduce(lambda x: int(x), self.ext_port.split('-'))

  def __eq__(self, other):
    if self.type == "any":
      return True
    elif self.type == "number":
      return self.ext_port == other
    elif self.type == "range":
      port_no = int(other) 
      return self.range[0] <= port_no and port_no <= self.range[1]
    else:
      raise Exception("WTF EXT PORT, port: %s type: %s" % (self.ext_port, self.type))

  def _is_integer(self, ext_port):
    try:
      int(ext_port)
      return True
    except ValueError:
      return False

class DomainNameField:

  def __init__(self, domain_name):
    self.domain_name = domain_name
    #Format WildCard Parsing
    if domain_name.startswith("*"):
      self.type = "wildcard"
    #Format Exact match
    else:
      self.type = "exact"

  def __eq__(self, other):
    if self.type == "wildcard":
      return other.endswith(self.domain_name[1:])
    elif self.type == "exact":
      return self.domain_name == other
    else:
      raise Exception('WTF DOMAIN NAME, domain: %s, type: %s' % (self.domain_name, self.type))

# TODO: You may want to add more classes/functions as well.
