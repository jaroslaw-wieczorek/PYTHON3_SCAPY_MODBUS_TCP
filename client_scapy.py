"""Scapy Client for ModbusTCP."""
# !/usr/bin/python3

from scapy.all import *
# from Modbus.Modbus import *
from scapy.contrib.modbus import *

import socket
from sys import argv
from math import ceil
from array import array
from struct import pack
from struct import unpack
from random import randint
from functools import reduce
import time
from argparse import ArgumentParser


def generateTraffic(host, unit):
    client = Client(host, unit)

    while True:
        try:
            fc = random.choice([1, 2, 3, 4, 5, 15, 16])
            add = random.randint(0, 65535)

            if fc in [1, 2]:
                print(fc)
                qua = random.randint(0, 2016)
                client.read(fc, add, qua)

            elif fc in [3, 4]:
                print(fc)
                qua = random.randint(0, 126)
                client.read(fc, add, qua)

            elif fc == 5:
                print(fc)
                outVal = random.randint(0, 2016)
                client.write(int(fc), int(add), str(outVal))

            elif fc == 6:
                print(fc)
                regVal = random.randint(0, 65535)
                client.write(fc, add, regVal)

            elif fc == 15:
                print(fc)
                qun = random.randint(1, 40)
                print(qun)
                dat = []
                dat.append(random.randint(0, 1))
                print(dat)
                for i in range(1, qun):
                    dat.append(random.randint(0, 1))
                client.write(fc, add, dat)

            elif fc == 16:
                print(fc)
                qun = random.randint(1, 40)
                print(qun)
                dat = []
                dat.append(random.randint(0, 65535))
                for i in range(1, qun):
                    dat.append(random.randint(0, 65535))
                client.write(fc, add, dat)

            delay = random.uniform(0.1, 1.5)
            time.sleep(delay)
        except Exception as err:
            print(err)
            break


def bytReq(n):
    """Count required bytes for number."""
    return int(ceil(int(n).bit_length() / 8))


class Client(object):
    """Docstring for Client."""

    def __init__(self, host='127.0.0.2', unit=1):
        """Init."""
        super(Client, self).__init__()

        self.host = '127.0.0.2'
        self.unit = unit
        self.port = 502

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        self.lADD = 0
        self.mADD = 0
        self.lLEN = 0
        self.mLEN = 0

        self.ADD = 0
        self.FC = 0
        self.LEN = 0
        self.BYT = 0
        self.VAL = 0
        self.DAT = []
        self.DAT_val = []
        self.TRANS_ID = 0

    def clear(self):
        self.lADD = 0
        self.mADD = 0
        self.lLEN = 0
        self.mLEN = 0

        self.ADD = 0
        self.FC = 0
        self.LEN = 0
        self.BYT = 0
        self.VAL = 0
        self.DAT = 0
        self.TRANS_ID = 0
        self.DAT_val = []

    def help(self):
        """Help."""
        print("Supported Function Codes:\n\
                1 = Read Coils or Digital Outputs\n\
                2 = Read Digital Inputs\n\
                3 = Read Holding Registers\n\
                4 = Read Input Registers\n\
                5 = Write Single Coil\n\
                6 = Write Single Register\n\
                15 = Write Coils or Digital Outputs\n\
                16 = Write Holding Registers")

    def read_build(self):
        """Read_build function."""
        self.TRANS_ID = randint(0, 255)
        self.buffer = None

        if self.FC == 1:
            name = "Read Coils"
            print("\nCreate Message with FC=%i:" % self.FC, name)
            cmd = ModbusADURequest(transId=self.TRANS_ID,
                                   protoId=0x0, len=0x6, unitId=1)

            cmd = cmd / ModbusPDU01ReadCoilsRequest(
                funcCode=self.FC,
                quantity=self.LEN,
                startAddr=self.ADD)

            cmd.show()

            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU01ReadCoilsResponse()

            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        elif self.FC == 2:
            name = "Read Discrete Inputs"
            print("\nCreate Message with FC=%i:" % self.FC, name)

            cmd = ModbusADURequest(transId=self.TRANS_ID,
                                   protoId=0x0, len=0x6, unitId=1)

            cmd = cmd / ModbusPDU02ReadDiscreteInputsRequest(
                funcCode=self.FC,
                quantity=self.LEN,
                startAddr=self.ADD)

            cmd.show()

            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU02ReadDiscreteInputsResponse()
            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        elif self.FC == 3:
            name = "Read Holding Registers"
            print("\nCreate Message with FC=%i:" % self.FC, name)

            cmd = ModbusADURequest(transId=self.TRANS_ID,
                                   protoId=0x0, len=0x6, unitId=1)
            cmd = cmd / ModbusPDU03ReadHoldingRegistersRequest(
                funcCode=self.FC,
                quantity=self.LEN,
                startAddr=self.ADD)

            cmd.show()

            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU03ReadHoldingRegistersResponse()
            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        elif self.FC == 4:
            name = "Read Input Registers Request"
            print("\nCreate Message with FC=%i:" % self.FC, name)

            cmd = ModbusADURequest(transId=self.TRANS_ID,
                                   protoId=0x0, len=0x6, unitId=1)

            cmd = cmd / ModbusPDU04ReadInputRegistersRequest(
                funcCode=self.FC,
                quantity=self.LEN,
                startAddr=self.ADD)

            cmd.show()

            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU04ReadInputRegistersResponse()
            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        else:
            self.help()

    def read(self, FC, ADD, LEN):
        """Read function."""
        # clear all old values
        self.clear()
        # setup new values
        self.FC = FC
        self.ADD = ADD
        self.LEN = LEN

        if self.FC not in [1, 2, 3, 4]:
            self.help()
        else:
            self.read_build()

    def write_build(self):
        """Write_build."""
        self.TRANS_ID = randint(0, 255)
        self.lADD = self.ADD & 0x00FF
        self.mADD = self.ADD >> 8
        self.VAL = b''
        self.DAT_val = []

        for index, data in enumerate(self.DAT):

            if self.FC not in [5, 6]:
                self.VAL = self.VAL + pack('>H', int(data))
                self.DAT[index] = int(data)
            else:
                self.VAL = self.VAL + pack('>H', int(data))

        if self.FC in [5, 6]:
            self.VAL = self.VAL[0:2]

        if self.FC in [5, 15]:
            self.LEN = len(self.VAL) * 8
        else:
            self.LEN = int(len(self.VAL) / 2)

        self.lLEN = self.LEN & 0x00FF
        self.mLEN = self.LEN >> 8

        for index, data in enumerate(self.VAL):
            self.DAT_val.append(int(self.VAL[index]))

        if self.FC == 5:
            name = "Write Single Coil Request"
            print("\nCreate Message with FC=%i:" % self.FC, name)

            cmd = ModbusADURequest(transId=self.TRANS_ID, len=0x6,
                                   protoId=0x0, unitId=1)

            cmd = cmd / ModbusPDU05WriteSingleCoilRequest(
                funcCode=self.FC,
                outputAddr=self.ADD,
                outputValue=0 if int(self.DAT) in [None, 0] else 0xFF00)

            print("FC5:=bytes(cmd)", bytes(cmd))
            cmd.show()

            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU05WriteSingleCoilResponse()

            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        elif self.FC == 6:
            name = "Write Single Register Request"
            print("\nCreate Message with FC=%i:" % self.FC, name)
            cmd = ModbusADURequest(transId=self.TRANS_ID,
                                   protoId=0x0, unitId=1,
                                   len=0x6)

            cmd = cmd / ModbusPDU06WriteSingleRegisterRequest(
                funcCode=self.FC,
                registerAddr=self.ADD,
                registerValue=int(self.DAT))

            cmd.show()
            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU06WriteSingleRegisterResponse()

            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        elif self.FC == 15:
            array_content = array(
                'B',
                [
                    0, 0, 0, 0, 0, 7 + len(self.VAL), self.unit, self.FC,
                    self.mADD, self.lADD, self.mLEN, self.lLEN, len(self.VAL)
                ]
            )

            array_content.extend(self.VAL)

            name = "Write Multiple Coils Request"
            print("\nCreate Message wit(bytesh FC=%i:" % self.FC, name)

            modbusADU = ModbusADURequest(transId=self.TRANS_ID, protoId=0x0,
                                         len=7 + len(self.VAL), unitId=0x1)

            modbusPDU0F = ModbusPDU0FWriteMultipleCoilsRequest(
                funcCode=self.FC,
                startingAddr=self.ADD,
                quantityOutput=self.LEN,
                byteCount=len(self.VAL),
                outputsValue=self.DAT_val)

            cmd = modbusADU / modbusPDU0F

            # cmd.show()
            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU0FWriteMultipleCoilsResponse()

            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(array('B', bytes(cmd)))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        elif self.FC == 16:
            array_content = array(
                'B',
                [
                    0, 0, 0, 0, 0, 7 + len(self.VAL),
                    self.unit, self.FC, self.mADD, self.lADD,
                    self.mLEN, self.lLEN, len(self.VAL)
                ]
            )

            array_content.extend(self.VAL)

            name = "Write Multiple Registers Request"
            print("\nCreate Message with FC=%i:" % self.FC, name)

            modbusADU = ModbusADURequest(
                transId=self.TRANS_ID, protoId=0x0,
                len=7 + len(self.VAL), unitId=0x1)

            modbusPDU10 = ModbusPDU10WriteMultipleRegistersRequest(
                funcCode=self.FC,
                startingAddr=self.ADD,
                quantityRegisters=self.LEN,
                byteCount=len(self.VAL),
                outputsValue=self.DAT_val)

            cmd = modbusADU / modbusPDU10

            # cmd.show()
            adu_res = ModbusADUResponse()
            pdu_res = ModbusPDU10WriteMultipleRegistersRequest()

            self.buffer = array('B', [0] * len(bytes(adu_res / pdu_res)))

            self.sock.send(bytes(cmd))
            self.sock.recv_into(self.buffer)
            print("Got response for FC=%i" % self.FC, self.buffer)

        else:
            help()

    def write(self, FC, ADD, DAT):
        """Write function."""
        # clear all old values
        self.clear()
        # setup new values
        self.FC = FC
        self.ADD = ADD
        self.DAT = DAT

        if FC not in [5, 6, 15, 16]:
            self.help()
        else:
            self.write_build()


def main():
    """Main."""
    parser = ArgumentParser(description="Modbus Client Program")

    parser.add_argument('-l', dest='loop', type=bool,
                        help="Loop bool [Default=False]", default=False)

    parser.add_argument('-i', dest='host', type=str,
                        help="Host Name or IP Address [Default=localhost]",
                        default="localhost")

    parser.add_argument('-u', dest='unit', type=int,
                        help="Unit Number [Default=1]", default=1)
    args = parser.parse_args()

    if args.loop is True:
        generateTraffic(args.host, args.unit)
    else:
        c = Client(args.host, args.unit)
    while True:
        S = input("Enter: FunctionCode, Address, Length " +
                  "of Registers to Read or Value of Registers to Write\n")

        L = S.strip().split(',')

        if int(L[0]) < 5 and int(L[0]) > 0:
            print("Received =", c.read(int(L[0]),
                                       int(L[1]),
                                       int(L[2])))

        elif int(L[0]) == 15 or int(L[0]) == 16:

            c.write(int(L[0]), int(L[1]), L[2:])

        elif int(L[0]) == 5 or int(L[0]) == 6:
            c.write(int(L[0]), int(L[1]), (L[2]))

        else:
            c.help()


if __name__ == "__main__":
    main()
