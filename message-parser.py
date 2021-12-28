
import message_parser
from scapy.contrib.modbus import *
from scapy.all import *

import subprocess


def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()        

    return ''.join([ "%02X" % ord( x ) for x in byteStr ]).strip()

def callback(pkt: Packet):                                                     
	if pkt.haslayer("ModbusADUResponse"):                                      
	    return pkt["ModbusADUResponse"]  


packets = sniff(offline="cap3.pcapng", prn=callback, count=200) 

# message = ByteToHex(str(bytes(packets[0]['ModbusADUResponse'])))
# message = ByteToHex(str(bytes(packets[0])))

message = "000112340006ff076d"
print("BYTES:",	message)





#message = bytes(packets[0]['ModbusADUResponse'])
#message = packets[0]['ModbusADUResponse']

subprocess.call("python3 message_parser.py -p tcp -m"+hex(binascii.a2b_hex(message)), shell=True)

print("done")
