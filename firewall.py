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

        protocol, ext_IP_address, ext_port, is_dns_pkt, domain_name = self.read_packet(pkt, pkt_dir)
        wrapped_packet = Wrap_Packet(protocol, ext_IP_address, ext_port, is_dns_pkt, domain_name)

        verdict = self.packet_lookup(wrapped_packet)

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

      return protocol, ext_IP_address, ext_port, is_dns_pkt, domain_name

    # Looks through the self.rules list and returns the verdict of the latest
    # rule in the list that matches the packet fields
    # Returns verdict==True if no rules in the list match the packet fields
    def packet_lookup(self, wrapped_packet):

    	# Set verdict initially to true so that if no rules match packet fields
    	# then the packet will be passed to the appropriate interface
    	verdict = True

    	for rule in self.rules:
    		if rule.protocol == wrapped_packet.protocol:
    			# Examine rule further since rule protocol matches packet protocol (TCP/UDP/ICMP)
    			if wrapped_packet.ext_IP_address == rule.ext_IP_address and wrapped_packet.ext_port == rule.ext_port:
    				verdict = rule.verdict
    		elif rule.protocol == "dns" and wrapped_packet.is_dns_pkt == true:
    			# Examine rule further since it is a DNS rule and packet is dns query
    			# wrapped_packet only has a domain_name field if is_dns_pkt is true for wrapped_packet
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
	def __init__(self, protocol, ext_IP_address, ext_port, is_dns_pkt, domain_name):
		self.protocol = protocol
    self.ext_IP_address = IPAddressField(ext_IP_address)
    self.ext_port = ExtPortField(ext_port)
    self.is_dns_pkt = is_dns_pkt
    if self.is_dns_pkt:
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
  		self.is_IP_prefix = true
  		# Element 0 is the IP, Element 1 is the slash #
  		_decimal_ip_and_prefix = other.ext_IP_address.split("/")
  		# Ask: any reason to make ip_to_int an instance function?
  		self._decimal_ip = self.ip_to_int(_decimal_ip_and_prefix[0])
  		self.slash_num = _decimal_ip_and_prefix[1]
  		self.relevant_portion = self.relevant_ip_portion(self._decimal_ip, self.slash_num)
    else:
      self.is_IP_prefix = false


  # Assume that the lhs of "==" is always the external IP address
  # of the packet, while the rhs is always the external Ip addr of the
  # rule that you're trying to match up with the packet
  def __eq__(self, other):
  	if other.ext_IP_address == "any":
  		return True
  	elif len(other.ext_IP_address) == 2:
  		# other.ext_IP_address is a 2-byte country code
  		return belongs_to_country(self.ext_IP_address, other.ext_IP_address)
  	elif other.is_IP_prefix:
  		# TODO: Deal with IP prefix case
  		decimal_ip = ip_to_int(self.ext_IP_address)
  		return self.relevant_ip_portion(decimal_ip, other.slash_num) == other.relevant_portion
  	else:
  		# other.ext_IP_address is just an IP address
  		return self.ext_IP_address == other.ext_IP_address

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
  	relevant_ip = 0xFFFFFFFF >> (32 - slash_num)
  	relevant_ip = 0xFFFFFFFF << (32 - slash_num)
  	return relevant_ip


class ExtPortField:

  def __init__(self, ext_port):
  	self.ext_port = ext_port
  	self.is_a_range = false
   	if "-" in self.ext_port:
  		self.is_a_range = true
  		self._temp_list = self.ext_port.split("-")
  		self.start_port = int(self._temp_list[0])
  		self.end_port = int(self._temp_list[1])

  # Assume that the lhs of "==" is always the external port
  # of the packet, while the rhs is always the external port of the
  # rule that you're trying to match up with the packet
  def __eq__(self, other):
  	if other.ext_port == "any":
  		return True
  	elif other.is_a_range == true:
      ext_port_as_int = int(self.ext_port)
  		return ext_port_as_int >= other.start_port and ext_port_as_int <= other.end_port
  	else:
  		# other.ext_port should be a single value
  		return self.ext_port == other.ext_port

  def _is_integer(self, ext_port):
    try:
      int(ext_port)
      return True
    except ValueError:
      return False

class DomainNameField:

  def __init__(self, domain_name):
  	self._domain_name = domain_name
  	self._intermediate_list = self._domain_name.split(".")
  	# self.rev_domain_name_list is the result of a string split into
  	# multiple elements by the . delimiter, followed by a reverse oper.
  	# that reverses the elements in the list
  	self.rev_domain_name_list = reversed(self._intermediate_list)

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
  	# Should never reach this part
  	raise Exception("WTF WE FUCKED UP")


# TODO: You may want to add more classes/functions as well.
