#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from collections import namedtuple

# TODO: Feel free to import any Python standard modules as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        parser = RulesParser(config['rule'])
        self.rules = parser.parse_rules()

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
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

Rule = namedtuple('Rule', ['verdict', 'protocol', 'ext_IP_address', 'ext_port'])
DNSRule = namedtuple('DNSRule', ['verdict', 'protocol', 'domain_name'])

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


# TODO: You may want to add more classes/functions as well.
