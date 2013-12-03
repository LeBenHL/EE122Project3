#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket, struct
from bisect import bisect_left
from datetime import datetime
import random
import re

# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
class MalformedPacketException(Exception):
  pass

class Firewall:

    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        #For traceroute XC
        self.traceroute_sources = {1: "192.168.122.1", 2: "192.168.122.2", 3: "192.168.122.3", 4: "192.168.122.4", 5: "192.168.122.5", 6: "192.168.122.6", 7: "192.168.122.7", 
          8: "192.168.122.8", 9: "192.168.122.9", 10: "192.168.122.10", 11: "192.168.122.11", 12: "192.168.122.12", 13: "192.168.122.122"}
        self.reverse_dns_domains = {"192.168.122.1": "prepare.for.trouble", "192.168.122.2": "make.it.double", "192.168.122.3": "to.protect.the.world.from.devastation", "192.168.122.4": "to.unite.all.peoples.within.our.nation", 
          "192.168.122.5": "to.denounce.the.evils.of.truth.and.love", "192.168.122.6": "to.extend.our.reach.to.the.stars.above", "192.168.122.7": "jessie", "192.168.122.8": "james", "192.168.122.9": "team.rocket.blast.off.at.the.speed.of.light", "192.168.122.10": "surrender.now.or.prepare.to.fight", "192.168.122.11": "meowth", "192.168.122.12": "thats.right", "192.168.122.122": "were.blasting.off.again"}

        #For HTTP Logging

        #Used to store HTTP Requests/Responses building them up from possibly fragmented packets
        self.http_tcp_conns = dict()

        try:
            self.lossy = True
            self.loss_percentage = float(config['loss'])
        except KeyError:
            self.lossy = False

        parser = RulesParser(config['rule'])
        self.rules, self.http_rules = parser.parse_rules()

    def handle_timer(self):
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):

        # TODO: need to add support for log http <host name>
        # Lossy Firewall
        if (self.lossy and self.loss_percentage > random.uniform(0, 100)):
          pass
        # Deal with nonlossy stuff here
        else:
          try:
            protocol, ext_IP_address, ext_port, check_dns_rules, domain_name, check_for_http_logging, QTYPE = self.read_packet(pkt, pkt_dir)
            wrapped_packet = WrappedPacket(protocol, ext_IP_address, ext_port, check_dns_rules, domain_name, check_for_http_logging)

            # verdict can be either 'pass', 'drop', 'deny'
            verdict = self.packet_lookup(wrapped_packet)

            if wrapped_packet.check_for_http_logging and verdict == "pass":
              self.handle_log_http(pkt, pkt_dir)
            else:
            # Useful stuff for debugging
            # if pkt_dir == PKT_DIR_INCOMING:
            #   #print "Incoming Verdict: %s, Protocol: %s, ext_IP_address: %s, ext_port: %s, domain_name: %s" % (verdict, protocol, ext_IP_address, ext_port, domain_name)
            #   pass
            # else:
            #   #print "Outgoing Verdict: %s, Protocol: %s, ext_IP_address: %s, ext_port: %s, domain_name: %s" % (verdict, protocol, ext_IP_address, ext_port, domain_name)
            #   pass
              if verdict == "pass":
                if pkt_dir == PKT_DIR_INCOMING:
                  self.iface_int.send_ip_packet(pkt)
                else: # pkt_dir == PKT_DIR_OUTGOING
                  #TRACEROUTE 192.168.122.122!
                  if protocol == "udp" and ext_IP_address == "192.168.122.122":
                    self.respond_to_traceroute(pkt)
                  elif protocol == "udp" and ext_port == 53 and QTYPE == 12:
                    ip_to_lookup = self.parse_ip_to_lookup(domain_name)

                    if ip_to_lookup.startswith("192.168.122"):
                      ip_section, transport_section, app_section = self.split_by_layers(pkt)
                      
                      #Generate Reverse DNS response
                      app_data = self.generate_reverse_DNS_response(app_section, domain_name, ip_to_lookup)

                      #Generate UDP header from the transport_section data and the app data
                      transport_header = self.generate_UDP_header(ip_section, transport_section, app_data)

                      #Generate IP header from the ip_section and payload
                      ip_header = self.generate_IP_header(ip_section, transport_header + app_data)

                      #Send the Constructed Packet to INT Interface
                      self.iface_int.send_ip_packet(ip_header + transport_header + app_data)
                    else:
                      self.iface_ext.send_ip_packet(pkt)
                  else:
                    self.iface_ext.send_ip_packet(pkt)
              elif verdict == "deny":
                # either deny tcp or deny dns
                if protocol == "tcp":
                  self.handle_deny_tcp(pkt, pkt_dir)
                else:
                  self.handle_deny_dns(domain_name, pkt)
              elif verdict == "drop":
                #Do Nothing to just drop it
                pass
          except IndexError as e:
            print e
            pass
          except MalformedPacketException as e:
            pass

    def respond_to_traceroute(self, pkt):
      #GET TTL Value
      TTL = struct.unpack("!B", pkt[8:9])[0]
      try:
        source = self.traceroute_sources[TTL]
      except KeyError:
        source = self.traceroute_sources[max(self.traceroute_sources.keys())]
    
      ip_section, transport_section, app_section = self.split_by_layers(pkt)

      if source == "192.168.122.122":
        TYPE = chr(3)
        CODE = chr(3)

      else:
        TYPE = chr(11)
        CODE = chr(0)

      UNUSED = struct.pack("!L", 0)

      IP_HEADER_PLUS_DATA = ip_section + transport_section[:8]

      CHECKSUM = self.calculate_checksum(self.calculate_sum(TYPE + CODE + UNUSED + IP_HEADER_PLUS_DATA))

      ICMP_DATA = TYPE + CODE + CHECKSUM + UNUSED + IP_HEADER_PLUS_DATA

      IP_HEADER = self.generate_IP_header(ip_section, ICMP_DATA, source=socket.inet_aton(source), protocol=chr(1))

      self.iface_int.send_ip_packet(IP_HEADER + ICMP_DATA)

    def generate_reverse_DNS_response(self, app_section, domain_name, ip_to_lookup):
      #Generate Reverse DNS response

      #Generate Header
      ID = app_section[0:2]
      QR_TO_RCODE = struct.pack('!H', 0b1000000000000000)
      QDCOUNT = struct.pack('!H', 1)
      ANCOUNT = struct.pack('!H', 1)
      NSCOUNT = struct.pack('!H', 0)
      ARCOUNT = struct.pack('!H', 0)

      HEADER = ID + QR_TO_RCODE + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

      #Generate Question Section
      QNAME = ""
      list_of_domain_parts = domain_name.split('.')
      for domain_part in list_of_domain_parts: 
        QNAME += chr(len(domain_part)) + bytes(domain_part)
      QNAME += chr(0)
      QTYPE = struct.pack('!H', 0x000c)
      QCLASS = struct.pack("!H", 0x0001)

      QUESTION = QNAME + QTYPE + QCLASS

      #Generate Answer Section
      NAME = QNAME
      TYPE = QTYPE
      CLASS = QCLASS
      TTL = struct.pack("!L", 0x00000001)
      RDATA = ""
      list_of_domain_parts = self.reverse_dns_domains[ip_to_lookup].split(".")
      for domain_part in list_of_domain_parts: 
        RDATA += chr(len(domain_part)) + bytes(domain_part)
      RDATA += chr(0)
      RDLENGTH = struct.pack('!H', len(RDATA))

      ANSWER = NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA

      return HEADER + QUESTION + ANSWER

    def parse_ip_to_lookup(self, domain_name):
      parts = domain_name.split(".")

      ip_parts = parts[0:4]
      ip_parts.reverse()

      return ".".join(ip_parts) 

    def handle_deny_tcp(self, pkt, pkt_dir):
      ip_section, transport_section, app_section = self.split_by_layers(pkt)

      #Generate TCP header from transport_section data; don't need app_section
      #Set RST flag = 1, set all other flags to 0
      transport_header = self.generate_TCP_header(ip_section, transport_section, set_rst=True)

      # Generate IP header from the ip_section and payload
      ip_header = self.generate_IP_header(ip_section, transport_header)

      if pkt_dir == PKT_DIR_INCOMING: # Packet came from EXT interface (source is outside world)
        self.iface_ext.send_ip_packet(ip_header + transport_header) # Send RST packet back to sender in outside world
      else: # Packet came from INT interfance (source is myself)
        self.iface_int.send_ip_packet(ip_header + transport_header) # Send RST packet back to sender

    def handle_log_http(self, pkt, pkt_dir):
      ip_section, transport_section, app_section = self.split_by_layers(pkt)
      if pkt_dir == PKT_DIR_OUTGOING: # is a HTTP request
        internal_port = struct.unpack("!H", transport_section[0:2])[0]
        if not self.http_tcp_conns.has_key(internal_port):
          self.http_tcp_conns[internal_port] = HttpTcpConnection(HttpTcpConnection.INACTIVE)

        connection = self.http_tcp_conns[internal_port]

        if connection.analyze(ip_section, transport_section, app_section, pkt_dir):
          self.iface_ext.send_ip_packet(pkt)

        self.log_http(connection)
        
      else: # is a HTTP response
        internal_port = struct.unpack("!H", transport_section[2:4])[0]

        if self.http_tcp_conns.has_key(internal_port):
          connection = self.http_tcp_conns[internal_port]

          if connection.analyze(ip_section, transport_section, app_section, pkt_dir):
            self.iface_int.send_ip_packet(pkt)

          self.log_http(connection)
        else:
          self.iface_int.send_ip_packet(pkt)

    def log_http(self, connection):
      if connection.full_request_header_received and connection.full_response_header_received and not connection.logged:
        connection.logged = True
        if self.match_http_rule(connection.host_name):
          log_file = open('http.log', 'a')
          log_line = "%s %s %s %s %s %s\n" % (connection.host_name, connection.method, connection.path, connection.version, connection.status_code, connection.object_size)
          print log_line
          log_file.write(log_line)
          log_file.flush()
          log_file.close()

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
        tcp_header_len = (tcp_header_len_tmp & 0xF0) >> 4
        al_index = tl_index + tcp_header_len * 4
      elif protocol_tmp == 17:
        #UDP
        al_index = tl_index + 8

      return (pkt[:tl_index], pkt[tl_index:al_index], pkt[al_index:])

    def generate_DNS_response(self, app_section, domain_name):
      #Generates a DNS response to the question

      #Generate Header
      ID = app_section[0:2]
      QR_TO_RCODE = struct.pack('!H', 0b1000000000000000)
      QDCOUNT = struct.pack('!H', 1)
      ANCOUNT = struct.pack('!H', 1)
      NSCOUNT = struct.pack('!H', 0)
      ARCOUNT = struct.pack('!H', 0)

      HEADER = ID + QR_TO_RCODE + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

      #Generate Question Section
      QNAME = ""
      list_of_domain_parts = domain_name.split('.')
      for domain_part in list_of_domain_parts: 
        QNAME += chr(len(domain_part)) + bytes(domain_part)
      QNAME += chr(0)
      QTYPE = struct.pack('!H', 0x0001)
      QCLASS = struct.pack("!H", 0x0001)

      QUESTION = QNAME + QTYPE + QCLASS

      #Generate Answer Section
      NAME = QNAME
      TYPE = QTYPE
      CLASS = QCLASS
      TTL = struct.pack("!L", 0x00000001)
      RDATA = socket.inet_aton("169.229.49.109")
      RDLENGTH = struct.pack('!H', len(RDATA))

      ANSWER = NAME + TYPE + CLASS + TTL + RDLENGTH + RDATA

      return HEADER + QUESTION + ANSWER

    def generate_UDP_header(self, ip_section, transport_section, app_data):
      #Reverse Src/Dest from original transport section
      #Checksum pseudocode from http://www.bloof.de/tcp_checksumming
      SOURCE_PORT = transport_section[2:4]
      DESTINATION_PORT = transport_section[0:2]

      LENGTH = struct.pack('!H', 8 + len(app_data))

      summation = self.calculate_sum(SOURCE_PORT + DESTINATION_PORT + LENGTH + app_data)

      #Add Pseudo Header to Summation
      summation += struct.unpack('!H', ip_section[12:14])[0] 
      summation += struct.unpack('!H', ip_section[14:16])[0] 
      summation += struct.unpack('!H', ip_section[16:18])[0] 
      summation += struct.unpack('!H', ip_section[18:20])[0] 
      summation += 8 + len(app_data)
      summation += 17 # UDP protocol number

      CHECKSUM = self.calculate_checksum(summation)

      return SOURCE_PORT + DESTINATION_PORT + LENGTH + CHECKSUM

    def generate_TCP_header(self, ip_section, transport_section, set_rst=False):
      #Reverse Src/Dest from original transport section
      #This is because we're sending a TCP RST packet back
      SOURCE_PORT = transport_section[2:4]
      DESTINATION_PORT = transport_section[0:2]

      # Set sender seqno. to ack=client_isn+1 since all TCP packets sent from receiver
      # have some sort of ack in them, where ack=client_isn+1
      # since we are the ones initializing the connection
      # Possibly bad logic?
      #SEQUENCE_NUM_INT = struct.unpack('!L', transport_section[8:12])[0] + 1
      #SEQUENCE_NUM = struct.pack('!L', SEQUENCE_NUM_INT)

      # Can be anything, since assume that sender is in SYN-SENT state
      # So if it receives a RST, it does not check sequence number field
      SEQUENCE_NUM = struct.pack('!L', 0x00000001)

      # Check the header 'Reset Processing here':
      # https://www.ietf.org/rfc/rfc793.txt
      # ACK_NUM = client_isn(source packet SEQNO field) + 1
      ACK_NUM_INT = struct.unpack('!L', transport_section[4:8])[0] + 1
      ACK_NUM = struct.pack('!L', ACK_NUM_INT)

      # Not sending any app data and no TCP options, so Offset = 5, Reserved = 0
      OFFSET_AND_RESERVED = chr((5 << 4) + 0)

      if set_rst==True:
        # Only set RST = 1, set all other flags to 0
        TCP_FLAGS = chr(0b00010100)
      else:
        TCP_FLAGS = chr(0)

      # According to Piazza post, can set both of these to 0
      # https://piazza.com/class/hjqfmgyat356br?cid=1069
      WINDOW = struct.pack('!H', 0x0000)
      URGENT_DATA_POINTER = struct.pack('!H', 0x0000)

      summation = self.calculate_sum(SOURCE_PORT + DESTINATION_PORT + SEQUENCE_NUM + ACK_NUM + OFFSET_AND_RESERVED + TCP_FLAGS + WINDOW + URGENT_DATA_POINTER)

      # According to Wikipedia, there is a Pseudo header involved
      # http://en.wikipedia.org/wiki/Transmission_Control_Protocol
      # Pseudo header includes source addr, destination addr,
      # protocol(zero-extended), and TCP length, where
      # TCP length = length of the TCP header and data (in bytes)
      summation += struct.unpack('!H', ip_section[12:14])[0]
      summation += struct.unpack('!H', ip_section[14:16])[0]
      summation += struct.unpack('!H', ip_section[16:18])[0]
      summation += struct.unpack('!H', ip_section[18:20])[0]
      summation += 20 # TCP length
      summation += 6 # TCP protocol number

      CHECKSUM = self.calculate_checksum(summation)

      return SOURCE_PORT + DESTINATION_PORT + SEQUENCE_NUM + ACK_NUM + OFFSET_AND_RESERVED + TCP_FLAGS + WINDOW + CHECKSUM + URGENT_DATA_POINTER

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

      if bytes_left > 0:
        summation += struck.unpack('!B', data[index:index+1])[0] << 8

      return summation

    def calculate_checksum(self, summation):
      #Calculates a checksum from the given summation
      #Pseudo Code from http://www.bloof.de/tcp_checksumming
      summation = (summation >> 16) + (summation & 0xFFFF)
      summation += (summation >> 16)

      return struct.pack('!H', ~summation & 0xFFFF)

    def generate_IP_header(self, ip_section, payload, source=None, dest=None, protocol=None):
      #Generate a return IP header by taking the original ip header minus options and updating the
      #IP Header Length, Total Length, Checksum, Src and Dest Fields
     
      VERSION_AND_HEADER_LENGTH = chr((4 << 4) + 5)
      TOS = chr(0)
      TOTAL_LENGTH = struct.pack('!H', len(payload) + 20)
      IDENTIFICATION_TO_TTL = ip_section[4:9]

      if protocol is None:
        PROTOCOL = ip_section[9]
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
        return (None, None, None, None, None, None, None)

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

      # check_for_http_logging determines whether or not a packet should be considered
      # for a "http log" rule matching. Initially set to False unless can prove otherwise.
      check_for_http_logging = False
      if protocol == "tcp" and ext_port == 80:
        check_for_http_logging = True

      # check_dns_rules determines whether or not a packet should be considered
      # for DNS rule matching. Initially set to False unless can prove otherwise.
      check_dns_rules = False
      domain_name = None
      QTYPE = None

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
      # Need to make sure to change the other return (None, None, None, None, None, None, None, None) to have the same # of elements
      return protocol, ext_IP_address, ext_port, check_dns_rules, domain_name, check_for_http_logging, QTYPE

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

    def match_http_rule(self, host_name):
      match_verdict = False

      for http_rule in self.http_rules:
        if NameField(host_name) == http_rule.host_name: # Should also cover IP address matching since no prefix, country codes, or "any" involved (Only simple string matching involved in IPv4 case)
          match_verdict = True
          break
      return match_verdict

class RulesParser:

  def __init__(self, filename):
    self.filename = filename

  def parse_rules(self):
    f = open(self.filename, 'r')
    rules = []
    http_rules = []
    for line in f:
      line = line.strip()
      #Ignore All lines that are blank or comment lines
      if line and not self._is_comment_line(line):
        rule = self.parse_line(line)
        if rule:
          if isinstance(rule, HTTPRule):
          	http_rules.append(rule)
          else:
          	rules.append(rule)
    return rules, http_rules

  def parse_line(self, line):
    tokens = line.split()
    #Make all tokens lowercase so we ignore case sensitivity
    tokens = map(lambda token: token.lower(), tokens)

    #Rules that have 4 fields are normal rules
    if len(tokens) == 4:
      return Rule(*tokens)
    #DNS Rules
    elif len(tokens) == 3:
      if tokens[0] == 'log': # This is a log http rule
        # tokens[2] is the host name
        return HTTPRule(tokens[2])
      else:
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

  def __init__(self, protocol, ext_IP_address, ext_port, check_dns_rules, domain_name, check_for_http_logging):
    self.protocol = protocol
    self.ext_IP_address = IPAddressField(ext_IP_address)
    self.ext_port = ExtPortField(ext_port)
    self.check_dns_rules = check_dns_rules
    self.domain_name = NameField(domain_name)
    self.check_for_http_logging = check_for_http_logging

class HTTPRule(Rule):
  def __init__(self, host_name):
    self.protocol = "http"
    self.host_name = NameField(host_name)

class DNSRule(Rule):

  def __init__(self, verdict, protocol, domain_name):
    self.verdict = verdict
    self.protocol = protocol
    self.domain_name = NameField(domain_name)

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


class NameField:

  def __init__(self, name):
    self.name = name

  # Assume that the lhs of "==" is always the domain name or host name
  # of the packet, while the rhs is always the domain name or host name of
  # the rule that you're trying to match up with the packet
  def __eq__(self, other):
    if other.name.startswith("*"):
      return self.name.endswith(other.name[1:])
    else:
      return self.name == other.name

#TODO - Ben, Reset Sequences? WTF Happens in this case
class HttpTcpConnection:

  #List of Possible States a Connection can be in
  CLIENT_INITIAL_SYN = 0
  SERVER_SYN_ACK = 1
  SENDING_DATA = 2
  DATA_DONE_SENDING = 3
  INACTIVE = 4

  MAX_32_BIT_INT = pow(2, 32)

  def __init__(self, state):
    self.state = state
    self.http_request_data = ""
    self.http_response_data = ""
    self.client_seqno = None
    self.server_seqno = None
    self.response_content_length_so_far = 0
    self.full_request_header_received = False
    self.full_response_header_received = False
    self.isn_client = None
    self.isn_server = None
    self.ext_IP_address = None

    #Fields to log
    self.host_name = None
    self.method = None
    self.path = None
    self.version = None
    self.status_code = None
    self.object_size = None
    self.logged = False
  
  #Given a Pkt and the direction of the packet, we can analyze it to see the state of our HttpTcpConnection
  #Return True if we want to pass the packet, False if we should drop it since it is out of order
  def analyze(self, ip_section, transport_section, app_section, pkt_dir):
    #print "ANALYZE"
    if self.state ==  HttpTcpConnection.DATA_DONE_SENDING:
      self.reset_http_data()

    is_syn_pkt = self.is_syn_pkt(transport_section)
    is_ack_pkt = self.is_ack_pkt(transport_section)
    is_fin_pkt = self.is_fin_pkt(transport_section)

    if pkt_dir == PKT_DIR_OUTGOING: # from client
      #print "NEW PACKET CLIENT"
      self.ext_IP_address = socket.inet_ntoa(ip_section[16:20])

      if is_syn_pkt:
        self.update_client_seq_no(transport_section)

      if is_ack_pkt:
        #Don't care about ACKS from client. No data to look at
        pass

      if is_fin_pkt:
        self.close_connection()

      if not is_syn_pkt and not is_fin_pkt:
        #Packet with our HTTP Data!
        seqno = struct.unpack('!L', transport_section[4:8])[0]
        if seqno == self.client_seqno: #Is the expected Seqno
          self.update_request_data(app_section)
        elif self.is_client_resubmission(seqno):
          pass
        else:
          #print "DROPPED CLIENT"
          return False

    else: # from server
      #print "NEW PACKET SERVER"
      self.ext_IP_address = socket.inet_ntoa(ip_section[12:16])

      if is_syn_pkt:
        #print "SYN"
        self.update_server_seq_no(transport_section)

      if is_ack_pkt:
        #Don't care about ACKS from server. No data to look at
        #print "ACK"
        pass

      if is_fin_pkt:
        #print "FIN"
        self.close_connection()

      if not is_syn_pkt and not is_fin_pkt:
        #print "DATA"
        #Packet with our HTTP Data!
        seqno = struct.unpack('!L', transport_section[4:8])[0]
        if seqno == self.server_seqno: #Is the expected Seqno
          self.update_response_data(app_section)
        elif self.is_server_resubmission(seqno):
          pass
        else:
          #print "DROPPED SERVER"
          return False

    #print "PASS"
    return True

  def is_syn_pkt(self, transport_section):
    return struct.unpack('!B', transport_section[13])[0] & 0x02

  def is_ack_pkt(self, transport_section):
    return struct.unpack('!B', transport_section[13])[0] & 0x10

  def is_fin_pkt(self, transport_section):
    return struct.unpack('!B', transport_section[13])[0] & 0x01

  def is_client_resubmission(self, seqno):
    if self.client_seqno:
      return (seqno < self.client_seqno and (self.client_seqno - seqno) < pow(2, 31)) or (seqno > self.client_seqno and (seqno - self.client_seqno) > pow(2, 31))
    else:
      #If we don't have a client_seqno, then TCP connection is not active now. Should probably send the packet and let
      #Server handle this unexpected packet.
      return True

  def is_server_resubmission(self, seqno):
    if self.server_seqno:
      return (seqno < self.server_seqno and (self.server_seqno - seqno) < pow(2, 31)) or (seqno > self.server_seqno and (seqno - self.server_seqno) > pow(2, 31))
    else:
      #If we don't have a client_seqno, then TCP connection is not active now. Should probably send the packet and let
      #Computer handle this unexpected packet.
      return True

  def update_client_seq_no(self, transport_section):
    if self.state == HttpTcpConnection.INACTIVE:
      #print "1st Handshake"
      self.state = HttpTcpConnection.CLIENT_INITIAL_SYN

      seqno = struct.unpack('!L', transport_section[4:8])[0]
      self.client_seqno = (seqno + 1) % HttpTcpConnection.MAX_32_BIT_INT
      self.isn_client = seqno % HttpTcpConnection.MAX_32_BIT_INT
    else:
      print "Updating Client Seq No when we are in State: %d" % self.state

  def update_server_seq_no(self, transport_section):
    if self.state == HttpTcpConnection.CLIENT_INITIAL_SYN:
      #print "2nd Handshake"
      self.state = HttpTcpConnection.SERVER_SYN_ACK

      seqno = struct.unpack('!L', transport_section[4:8])[0]
      self.server_seqno = (seqno + 1) % HttpTcpConnection.MAX_32_BIT_INT
      self.isn_server = seqno % HttpTcpConnection.MAX_32_BIT_INT
    else:
      print "Updating Server Seq No when we are in State: %d" % self.state

  def update_request_data(self, app_section):
    if self.state == HttpTcpConnection.SERVER_SYN_ACK or self.state == HttpTcpConnection.SENDING_DATA:
      self.state = HttpTcpConnection.SENDING_DATA
      self.client_seqno = (self.client_seqno + len(app_section)) % HttpTcpConnection.MAX_32_BIT_INT

      if self.full_request_header_received:
        pass
      else:
        self.http_request_data += app_section
        self.attempt_to_parse_request()

    else:
      print "Updating Request data when we are in State: %d" % self.state

  def attempt_to_parse_request(self):
    if self.http_request_data == "":
      return
    lines = re.split("\r?\n", self.http_request_data)
    if "" in lines:
      self.full_request_header_received = True
      request_line = lines[0].split()
      self.method = request_line[0]
      self.path = request_line[1]
      self.version = request_line[2]

      found_host_name = False
      for line in lines:
        stripped_line = line.strip()
        if stripped_line.startswith("Host:"):
          self.host_name = stripped_line.split()[1]
          found_host_name = True

      if not found_host_name:
        self.host_name = self.ext_IP_address

  def update_response_data(self, app_section):
    if self.state == HttpTcpConnection.SENDING_DATA:
      self.server_seqno = (self.server_seqno + len(app_section)) % HttpTcpConnection.MAX_32_BIT_INT

      if self.full_response_header_received:
        self.response_content_length_so_far += len(app_section)
      else:
        self.http_response_data += app_section
        self.attempt_to_parse_response()

      self.check_for_complete_response()

    else:
      print "Updating Response data when we are in State: %d" % self.state

  def attempt_to_parse_response(self):
    if self.http_response_data == "":
      return
    result = re.match("(([\s\S]*?\r?\n)*?)\r?\n([\s\S]*?)", self.http_response_data)
    if result:
      self.full_response_header_received = True
      header = result.group(1)
      lines = re.split("\r?\n", header)
      response_line = lines[0].split()
      self.status_code = response_line[1]

      found_content_length = False
      for line in lines:
        if line.strip().startswith("Content-Length:"):
          self.object_size = int(line.split()[1])
          found_content_length = True

      if not found_content_length:
        self.object_size = -1

      http_object = result.group(3)
      self.response_content_length_so_far += len(http_object)

  def check_for_complete_response(self):
    #print (self.response_content_length_so_far, self.object_size)
    #print self
    if self.response_content_length_so_far == self.object_size:
      self.state = HttpTcpConnection.DATA_DONE_SENDING
    #print

  def close_connection(self):
    if self.state == HttpTcpConnection.DATA_DONE_SENDING or self.state == HttpTcpConnection.SENDING_DATA:
      #print "Close"
      self.state = HttpTcpConnection.INACTIVE
      self.http_request_data = ""
      self.http_response_data = ""
      self.client_seqno = None
      self.server_seqno = None
      self.response_content_length_so_far = 0
      self.full_request_header_received = False
      self.full_response_header_received = False
      self.isn_client = None
      self.isn_server = None
      self.ext_IP_address = None

      self.host_name = None
      self.method = None
      self.path = None
      self.version = None
      self.status_code = None
      self.object_size = None
      self.logged = False
    else:
      """
      Two Fin packets are sent when closing a connection, one from the client, one from the server
      We set our connection state to inactive when we see the first fin which means the second fin
      does nothing. I just put this here to silent the state machine error we see since its not much
      an error and I don't want to deal with having a middle man state between active and inactive 
      connections
      """
      if self.state != HttpTcpConnection.INACTIVE:
        print "Closing connection when we are in State: %d" % self.state

  def reset_http_data(self):
    if self.state == HttpTcpConnection.DATA_DONE_SENDING:
      #print "Reset"
      self.state = HttpTcpConnection.SENDING_DATA
      self.http_request_data = ""
      self.http_response_data = ""
      self.response_content_length_so_far = 0
      self.full_request_header_received = False
      self.full_response_header_received = False
      self.isn_client = None
      self.isn_server = None
      self.ext_IP_address = None

      self.host_name = None
      self.method = None
      self.path = None
      self.version = None
      self.status_code = None
      self.object_size = None
      self.logged = False
    else:
      print "Reseting HTTP Data when we are in State: %d" % self.state

# TODO: You may want to add more classes/functions as well.
