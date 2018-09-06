"""Scapy Client for ModbusTCP."""
# !/usr/bin/python3

from scapy.all import *
# from Modbus.Modbus import *
from scapy.contrib.modbus import *


counter = 0
list_modbus_data = []
filename = "wszystkie_zmienne_procesowe"

import csv


myfile = open(filename, 'w+')
wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)


def sniff_callback(pkt):
    global counter, wr

    if pkt.haslayer(ModbusADURequest):
        a = pkt["ModbusADURequest"]
        req = ["ModbusADURequest", a.transId, a.protoId, a.len, a.unitId, []]

        if pkt.haslayer(ModbusPDU01ReadCoilsRequest):
            b = pkt["ModbusPDU01ReadCoilsRequest"]
            req[5] = [b.funcCode, b.startAddr, b.quantity]

        elif pkt.haslayer(ModbusPDU02ReadDiscreteInputsRequest):
            b = pkt["ModbusPDU02ReadDiscreteInputsRequest"]
            req[5] = [b.funcCode, b.startAddr, b.quantity]

        elif pkt.haslayer(ModbusPDU03ReadHoldingRegistersRequest):
            b = pkt["ModbusPDU03ReadHoldingRegistersRequest"]
            req[5] = [b.funcCode, b.startAddr, b.quantity]

        elif pkt.haslayer(ModbusPDU04ReadInputRegistersRequest):
            b = pkt["ModbusPDU04ReadInputRegistersRequest"]
            req[5] = [b.funcCode, b.startAddr, b.quantity]

        elif pkt.haslayer(ModbusPDU05WriteSingleCoilRequest):
            b = pkt["ModbusPDU05WriteSingleCoilRequest"]
            req[5] = [b.funcCode, b.outputAddr, b.outputValue]

        elif pkt.haslayer(ModbusPDU06WriteSingleRegisterRequest):
            b = pkt["ModbusPDU06WriteSingleRegisterRequest"]
            req[5] = [b.funcCode, b.registerAddr, b.registerValue]

        elif pkt.haslayer(ModbusPDU07ReadExceptionStatusRequest):
            b = pkt["ModbusPDU07ReadExceptionStatusRequest"]
            req[5] = [b.funcCode]

        elif pkt.haslayer(ModbusPDU0FWriteMultipleCoilsRequest):
            b = pkt["ModbusPDU0FWriteMultipleCoilsRequest"]
            req[5] = [b.funcCode, b.startingAddr, b.quantityOutput, b.byteCount, b.outputsValue]
        wr.writerow(req)

    elif pkt.haslayer(ModbusADUResponse):
        a = pkt["ModbusADUResponse"]
        req = ["ModbusADUResponse", a.transId, a.protoId, a.len, a.unitId, []]

        if pkt.haslayer(ModbusPDU01ReadCoilsResponse):
            b = pkt["ModbusPDU01ReadCoilsResponse"]
            req[5] = [b.funcCode, b.byteCount, b.coilStatus]

        elif pkt.haslayer(ModbusPDU02ReadDiscreteInputsResponse):
            b = pkt["ModbusPDU02ReadDiscreteInputsResponse"]
            req[5] = [b.funcCode, b.byteCount, b.inputStatus]

        elif pkt.haslayer(ModbusPDU03ReadHoldingRegistersResponse):
            b = pkt["ModbusPDU03ReadHoldingRegistersResponse"]
            req[5] = [b.funcCode, b.byteCount, b.registerVal]

        elif pkt.haslayer(ModbusPDU04ReadInputRegistersResponse):
            b = pkt["ModbusPDU04ReadInputRegistersResponse"]
            req[5] = [b.funcCode, b.byteCount, b.registerVal]

        elif pkt.haslayer(ModbusPDU05WriteSingleCoilResponse):
            b = pkt["ModbusPDU05WriteSingleCoilResponse"]
            req[5] = [b.funcCode, b.outputAddr, b.outputValue]

        elif pkt.haslayer(ModbusPDU06WriteSingleRegisterResponse):
            b = pkt["ModbusPDU06WriteSingleRegisterResponse"]
            req[5] = [b.funcCode, b.registerAddr, b.registerValue]

        elif pkt.haslayer(ModbusPDU07ReadExceptionStatusResponse):
            b = pkt["ModbusPDU07ReadExceptionStatusResponse"]
            req[5] = [b.funcCode, b.startingAddr]

        elif pkt.haslayer(ModbusPDU0FWriteMultipleCoilsResponse):
            b = pkt["ModbusPDU0FWriteMultipleCoilsResponse"]
            req[5] = [b.funcCode, b.startingAddr, b.quantityOutput]
        wr.writerow(req)
    counter += 1
    if counter % 10000 == 0:
        print(counter)

def sniff_packets(filename):
    print("Sniff")
    global list_modbus_data

    packets = sniff(offline=filename, prn=sniff_callback)



def main():
    global wr, myfile
    filename = "bms.pcap"
    sniff_packets(filename)
    myfile.close()

if __name__ == '__main__':
    main()
