# Lab 3 Skeleton
#
# Based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.tcp import tcp
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    if packet.type == ethernet.ARP_TYPE:
      msg = of.ofp_flow_mod()
      msg.match.dl_type = 0x0806
      msg.priority = 10
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)
      msg = of.ofp_packet_out()
      msg.data = packet_in
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)
      return
    if packet.type == ethernet.IP_TYPE and isinstance(packet.next.next, tcp):
      msg = of.ofp_flow_mod()
      msg.match.dl_type = 0x0800
      msg.match.nw_proto = 6
      msg.priority = 9
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)
      msg = of.ofp_packet_out()
      msg.data = packet_in
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      self.connection.send(msg)
      return
    if packet.type == ethernet.IP_TYPE:
      msg = of.ofp_flow_mod()
      msg.match.dl_type = 0x0800
      msg.priority = 1
      self.connection.send(msg)
      return




  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)