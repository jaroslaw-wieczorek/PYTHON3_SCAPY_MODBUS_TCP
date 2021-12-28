#!/usr/bin/env python
# coding: utf-8

# In[85]:


from kaitaistruct import * 
from scapy.all import * 
from scapy.contrib.modbus import *


# In[86]:


from pathlib import Path

cwd = Path().resolve()
print(cwd)

lib_path = os.path.abspath(os.path.join(cwd))
sys.path.append(lib_path)


# In[87]:


counter = 0
def callback(pkt):
    global counter
    print(counter) 
    pkt.show()
    counter += 1
    
packets = sniff(offline=lib_path + "/data/pcaps/cap3.pcapng", prn=callback, count=100)


# In[88]:


with open(lib_path+"/data/binary/pkt", "wb+") as file:
    file.write(bytes(packets[0]))
    file.write(bytes(packets[1]))
    file.write(bytes(packets[2]))
 


# In[89]:


with open(lib_path+"/data/binary/only_modbus", "wb") as file:
    file.write(bytes(packets[0]['TCP'].payload))


# In[90]:


print(cwd)


# In[91]:


from kaitaistruct import KaitaiStream, BytesIO
from src.kaitai_py.ethernet_frame import EthernetFrame
from src.kaitai_py.udp_datagram import UdpDatagram
from src.kaitai_py.tcp_segment import TcpSegment
from src.kaitai_py.icmp_packet import IcmpPacket
from src.kaitai_py.ipv6_packet import Ipv6Packet
from src.kaitai_py.ipv4_packet import Ipv4Packet

raw = (bytes(packets[2]))

data = EthernetFrame(KaitaiStream(BytesIO(raw)))


# In[92]:


data
#data = EthernetFrame.from_file(lib_path+"/kaitai/dane/pkt")


# In[93]:


print('ttl:', data.body.ttl)


# In[94]:


data.body.body


# In[95]:


data.body.body.body


# In[96]:



from __future__ import print_function
import collections
import textwrap
from optparse import OptionParser
import codecs as c

from pymodbus.factory import ClientDecoder, ServerDecoder
from pymodbus.transaction import ModbusSocketFramer
from pymodbus.transaction import ModbusBinaryFramer
from pymodbus.transaction import ModbusAsciiFramer
from pymodbus.transaction import ModbusRtuFramer
from pymodbus.compat import  IS_PYTHON3


class Decoder(object):

    def __init__(self, framer, encode=False):
        """ Initialize a new instance of the decoder
        :param framer: The framer to use
        :param encode: If the message needs to be encoded
        """
        self.framer = framer
        self.encode = encode
        self.name = None
        self.unit = None
    
    def decode(self, message):
        """ Attempt to decode the supplied message
        :param message: The messge to decode
        """

        value = message if self.encode else c.encode(message, 'hex_codec')
        print("="*80)
        print("Decoding Message %s" % value)
        print("="*80)
        decoders = [
            self.framer(ServerDecoder(), client=None),
            self.framer(ClientDecoder(), client=None)
        ]
        for decoder in decoders:
            print("%s" % decoder.decoder.__class__.__name__)
            print("-"*80)
            try:
                decoder.addToFrame(message)
                if decoder.checkFrame():
                    self.unit = decoder._header.get("uid", 0x00)
                    unit = decoder._header.get("uid", 0x00)
                    decoder.advanceFrame()
                    decoder.processIncomingPacket(message, self.report, unit)
                else:
                    self.check_errors(decoder, message)
            except Exception as ex:
                self.check_errors(decoder, message)

    def check_errors(self, decoder, message):
        """ Attempt to find message errors
        :param message: The message to find errors in
        """
        print("Unable to parse message - {} with {}".format(message,
                                                                decoder))

    def report(self, message):
        """ The callback to print the message information
        :param message: The message to print
        """
        
        print("%-15s = %s" % ('name', message.__class__.__name__))
        for (k, v) in message.__dict__.items():
            if isinstance(v, dict):
                print("%-15s =" % k)
                for kk,vv in v.items():
                    print("  %-12s => %s" % (kk, vv))

            elif isinstance(v, collections.Iterable):
                print("%-15s =" % k)
                value = str([int(x) for x  in v])
                for line in textwrap.wrap(value, 60):
                    print("%-15s . %s" % ("", line))
            else:
                print("%-15s = %s" % (k, hex(v)))
        print("%-15s = %s" % ('documentation', message.__doc__))


# -------------------------------------------------------------------------- #
# and decode our message
# -------------------------------------------------------------------------- #

def get_messages(option):
    """ A helper method to generate the messages to parse
    :param options: The option manager
    :returns: The message iterator to parse
    """
    if option.message:
        if option.transaction:
            msg = ""
            for segment in option.message.split():
                segment = segment.replace("0x", "")
                segment = "0" + segment if len(segment) == 1 else segment
                msg = msg + segment
            option.message = msg

        if not option.ascii:
            if not IS_PYTHON3:
                option.message = option.message.decode('hex')
            else:
                option.message = c.decode(option.message.encode(), 'hex_codec')
        yield option.message
    elif option.file:
        with open(option.file, "r") as handle:
            for line in handle:
                if line.startswith('#'): continue
                if not option.ascii:
                    line = line.strip()
                    line = line.decode('hex')
                yield line


def main():
    """ 
        The main runner function
    """
    #option = get_options()


    framer = ModbusSocketFramer
    decoder = Decoder(framer)
    decoder.decode(data.body.body.body)


main()


# In[ ]:





# In[ ]:





# In[ ]:




