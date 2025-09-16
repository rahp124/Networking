from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr

log = core.getLogger()

class Final (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def handle_arp(self, arp_header, switch_id, source_port):
    target_ip = str(arp_header.protodst)
    
    if switch_id == 1:
      if target_ip.startswith('128.114.1.'):
        return 1
      elif target_ip.startswith('128.114.2.'):
        return 2
      elif target_ip == '128.114.3.178':
        return 3
      elif target_ip == '192.47.38.109':
        return 4
      elif target_ip == '108.35.24.113':
        return 5
    
    elif switch_id == 2:
      if target_ip in ['128.114.1.101', '128.114.1.102', '128.114.1.103', '128.114.1.104']:
        if target_ip == '128.114.1.101':
          return 2
        elif target_ip == '128.114.1.102':
          return 3
        elif target_ip == '128.114.1.103':
          return 4
        elif target_ip == '128.114.1.104':
          return 5
      else:
        return 1
    
    elif switch_id == 3:
      if target_ip in ['128.114.2.201', '128.114.2.202', '128.114.2.203', '128.114.2.204']:
        if target_ip == '128.114.2.201':
          return 2
        elif target_ip == '128.114.2.202':
          return 3
        elif target_ip == '128.114.2.203':
          return 4
        elif target_ip == '128.114.2.204':
          return 5
      else:
        return 1
    
    elif switch_id == 4:
      if target_ip == '128.114.3.178':
        return 2
      else:
        return 1
    
    return None

  def handle_ip(self, ip_header, switch_id, source_port):
    dest_ip = str(ip_header.dstip)
    
    if switch_id == 1:
      if dest_ip.startswith('128.114.1.'):
        return 1
      elif dest_ip.startswith('128.114.2.'):
        return 2
      elif dest_ip == '128.114.3.178':
        return 3
      elif dest_ip == '192.47.38.109':
        return 4
      elif dest_ip == '108.35.24.113':
        return 5
    
    elif switch_id == 2:
      if dest_ip == '128.114.1.101':
        return 2
      elif dest_ip == '128.114.1.102':
        return 3
      elif dest_ip == '128.114.1.103':
        return 4
      elif dest_ip == '128.114.1.104':
        return 5
      else:
        return 1
    
    elif switch_id == 3:
      if dest_ip == '128.114.2.201':
        return 2
      elif dest_ip == '128.114.2.202':
        return 3
      elif dest_ip == '128.114.2.203':
        return 4
      elif dest_ip == '128.114.2.204':
        return 5
      else:
        return 1
    
    elif switch_id == 4:
      if dest_ip == '128.114.3.178':
        return 2
      else:
        return 1
    
    return None

  def get_destination_port(self, packet, switch_id, source_port):
    arp_header = packet.find('arp')
    if arp_header is not None:
      return self.handle_arp(arp_header, switch_id, source_port)
    
    ip_header = packet.find('ipv4')
    if ip_header is not None:
      return self.handle_ip(ip_header, switch_id, source_port)
    
    return None

  def should_drop_packet(self, packet, switch_id, source_port):
    ip_header = packet.find('ipv4')
    if ip_header is None:
      return False
    
    src_ip = str(ip_header.srcip)
    dest_ip = str(ip_header.dstip)
    icmp_header = packet.find('icmp')
    
    if src_ip == '108.35.24.113' and icmp_header is not None:
      if dest_ip.startswith('128.114.1.'):
        return True
      if dest_ip.startswith('128.114.2.'):
        return True
      if dest_ip == '128.114.3.178':
        return True
    
    if src_ip == '108.35.24.113' and dest_ip == '128.114.3.178':
      return True
    
    if src_ip == '192.47.38.109' and icmp_header is not None:
      if dest_ip.startswith('128.114.2.'):
        return True
      if dest_ip == '128.114.3.178':
        return True
    
    if src_ip == '192.47.38.109' and dest_ip == '128.114.3.178':
      return True
    
    if src_ip.startswith('128.114.1.') and dest_ip.startswith('128.114.2.') and icmp_header is not None:
      return True
    if src_ip.startswith('128.114.2.') and dest_ip.startswith('128.114.1.') and icmp_header is not None:
      return True
    
    return False

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    if self.should_drop_packet(packet, switch_id, port_on_switch):
      log.info("Firewall: Dropping packet from switch %s port %s", switch_id, port_on_switch)
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet)
      msg.idle_timeout = 30
      msg.hard_timeout = 30
      msg.data = packet_in
      self.connection.send(msg)
      return
    
    dest_port = self.get_destination_port(packet, switch_id, port_on_switch)
    
    if dest_port is None:
      log.info("Dropping unknown packet type from switch %s port %s", switch_id, port_on_switch)
      return
    
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 30
    msg.hard_timeout = 30
    
    msg.actions.append(of.ofp_action_output(port = dest_port))
    msg.data = packet_in
    self.connection.send(msg)
    
    log.info("Installing flow: switch %s, port %s to %s", switch_id, port_on_switch, dest_port)

  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)