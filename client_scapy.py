#!/usr/bin/python3

from scapy.all import *
from Modbus.Modbus import *

import socket
from sys import argv
from math import ceil
from array import array
from struct import pack
from struct import unpack
from random import randint
from argparse import ArgumentParser


class Client(object):
    """Docstring for Client."""

    def __init__(self, host='localhost', unit=1, loop=False):
        """Init."""
        super(Client, self).__init__()

        self.host = "127.0.0.1"
        self.unit = unit
        self.port = 502
        self.loop = loop

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
        self.DAT = 0
        self.numberREG = 0
        self.transId = 0

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
        # Low Bits
        self.lADD = self.ADD & 0x00FF

        # Big Bits
        self.mADD = self.ADD >> 8

        # Low Bits
        self.lLEN = self.LEN & 0x00FF

        # Big Bits
        self.mLEN = self.LEN >> 8

        self.buffer = None

        if (self.FC < 3):
            # Zaokrąglanie liczby bytów
            self.BYT = ceil(self.LEN / 8)  # Round off the no. of bytes
        else:
            self.BYT = self.LEN * 2

        if self.FC == 1:
            # ModbusADU().default_fields
            # {'len': None, 'protoId': 0, 'transId': 1, 'unitId': 0}

            # ModbusPDU01_Read_Coils
            # {'funcCode': 1, 'quantity': 1, 'startAddr': 0}

            cmd = ModbusADU(transId=randint(0, 255), protoId=0, unitId=1)
            cmd = cmd/ModbusPDU01_Read_Coils(funcCode=self.FC,
                                             quantity=self.LEN,
                                             startAddr=self.ADD)
            # cmd = ModbusPDU01_Read_Coils()
            cmd.show()
            print("Send FC=1 Read Coils")
            return bytes(cmd)

        elif self.FC == 2:
            cmd = ModbusADU(transId=randint(0, 255), protoId=0, unitId=1)
            cmd = cmd/ModbusPDU02_Read_Discrete_Inputs(funcCode=self.FC,
                                                       quantity=self.LEN,
                                                       startAddr=self.ADD)
            cmd.show()
            print("Send FC=2 Read Discrete Inputs")
            return bytes(cmd)

        elif self.FC == 3:
            cmd = ModbusADU(transId=randint(0, 255), protoId=0, unitId=1)
            cmd = cmd/ModbusPDU03_Read_Holding_Registers(funcCode=self.FC,
                                                         quantity=self.LEN,
                                                         startAddr=self.ADD)
            cmd.show()
            print("Send FC=3 Read Holding Registers")
            return bytes(cmd)

        elif self.FC == 4:
            cmd = ModbusADU(transId=randint(0, 255), protoId=0, unitId=1)
            cmd = cmd/ModbusPDU04_Read_Input_Registers(funcCode=self.FC,
                                                       quantity=self.LEN,
                                                       startAddr=self.ADD)
            cmd.show()
            print("Send FC=4 Read Input Registers")
            return bytes(cmd)

        else:
            return None

    def read(self, FC, ADD, LEN):
        """read"""
        self.FC = FC
        self.ADD = ADD
        self.LEN = LEN

        if self.FC not in [1, 2, 3, 4]:
            self.help()
        else:
            cmd = self.read_build()

            if cmd is None:
                self.help()
            else:
                self.sock.send(cmd)

                # TO CHANGE IN THE FUTURE ON ONLY SCAPY
                self.buffer = array('B', [0] * (self.BYT + 9))

                # For received all packages
                self.sock.recv_into(self.buffer)

                # self.sock.recv_into(buffer)
                print("buffer:", self.buffer)

            if (self.FC > 2):
                # TO CHANGE IN THE FUTURE ON ONLY SCAPY
                self.req = unpack('>' + 'H' * self.LEN,
                                  self.buffer[9:(9 + self.BYT)])
                # print(self.req)
            else:
                # TO CHANGE IN THE FUTURE ON ONLY SCAPY
                self.req = unpack('B' * self.BYT,
                                  self.buffer[9:(9 + self.BYT)])
                # print(self.req)

    def write_build(self):
        """Write_build."""
        # Przygotowanie wartości
        self.lADD = self.ADD & 0x00FF
        self.mADD = self.ADD >> 8
        self.VAL = b''
        self.transId = randint(0, 255)

        print(self.DAT)
        for i in self.DAT:

            self.VAL = self.VAL + pack('>H', int(i))
            self.numberREG += 1

        if self.FC == 5 or self.FC == 6:
            self.VAL = self.VAL[0:2]
            print(self.VAL)

        if self.FC == 5 or self.FC == 15:
            self.LEN = len(self.VAL) * 8
        else:
            self.LEN = int(len(self.VAL) / 2)

        self.lLEN = self.LEN & 0x00FF
        self.mLEN = self.LEN >> 8
        print(self.lLEN)

        if self.FC == 5:
            transId = randint(0, 255)
            # FC read Coils or Digital Outputs == ModbusPDU01_Read_Coils
            print("VAL:", self.VAL, "Len", self.lLEN)

            cmd = array('B', [0, 0, 0, 0, 0, 7 + len(self.VAL),
                              self.unit, self.FC, self.mADD, self.lADD,
                              self.mLEN, self.lLEN, len(self.VAL)])

            print("Oryginal: ", cmd)
            # 0000   00 80 f4 00 01 01 00 00 86 5a eb 20 08 00 45 00
            # 0010   00 34 30 58 40 00 80 06 44 9e c0 a8 02 64 c0 a8
            # 0020   02 19 04 8d 01 f6 87 a7 91 e3 59 79 46 01 50 18
            # 0030   ff ff 6c 5d 00 00 00 00 00 00 00 06 ff 05 00 00
            # 0040   ff 00
            print(int(self.DAT))

            cmd = ModbusADU(transId=transId, protoId=0, len=6, unitId=1)
            cmd = cmd/ModbusPDU05_Write_Single_Coil(
                    funcCode=self.FC,
                    outputAddr=self.ADD,
                    outputValue=0 if int(self.DAT) is None or 0 else 0xFF00)

            print("SCAPY:", bytes(cmd))
            cmd.show()
            return bytes(cmd)

        elif self.FC == 6:
            cmd = ModbusADU(transId=self.transId, protoId=0, unitId=1, len=6)
            cmd = cmd/ModbusPDU06_Write_Single_Register(
                    funcCode=self.FC,
                    registerAddr=self.ADD,
                    registerValue=int(self.DAT))

            cmd.show()
            return bytes(cmd)

        elif self.FC == 15:
            cmd = ModbusADU(transId=self.transId, len=len(self.VAL),
                            protoId=0, unitId=1)

            cmd = cmd/ModbusPDU0F_Write_Multiple_Coils(
                        funcCode=self.FC,
                        startingAddr=self.ADD,
                        quantityRegisters=self.numberREG,
                        byteCount=len(bytes(0)),
                        outputsValue=self.DAT)
            cmd.show()
            return bytes(cmd)

        elif self.FC == 16:
            cmd = ModbusADU(transId=self.transId, protoId=0,
                            unitId=1, len=len(self.VAL))

            cmd = cmd/ModbusPDU10_Write_Multiple_Registers(
                        funcCode=self.FC,
                        startingAddr=self.ADD,
                        quantityRegisters=self.numberREG,
                        byteCount=len(bytes(0)),
                        outputsValue=self.DAT)
            cmd.show()

            return bytes(cmd)
        else:
            return None

    def write(self, FC, ADD, DAT):
        """Write."""
        if FC not in [5, 6, 15, 16]:
            self.help()
            print("FC is not in")
        else:
            self.FC = FC
            self.ADD = ADD
            self.DAT = DAT

            cmd = self.write_build()

            if cmd is None:
                self.help()
            else:
                buffer = array('B', [0] * 8)

                self.sock.send(cmd)
                self.sock.recv_into(buffer)
                print("buffer:", buffer)


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
    c = Client(args.host, args.unit, args.loop)

    while True:
        S = input("Enter: FunctionCode, Address, Length of Registers "
                  + "to Read or Value of Registers to Write\n")
        L = S.strip().split(',')

        if c.loop is True:
            while True:
                if (int(L[0]) < 5 and int(L[0]) > 0):
                    print("Received =", c.read(int(L[0]),
                                               int(L[1]),
                                               int(L[2])))

                elif (int(L[0]) == 15 or int(L[0]) == 16):
                    c.write(int(L[0]), int(L[1]), L[2:])

                elif (int(L[0]) == 5 or int(L[0]) == 6):
                    c.write(int(L[0]), int(L[1]), L[2])

                else:
                    c.help()
        else:
            if (int(L[0]) < 5 and int(L[0]) > 0):
                print("Received =", c.read(int(L[0]),
                                           int(L[1]),
                                           int(L[2])))

            elif (int(L[0]) == 15 or int(L[0]) == 16):
                c.write(int(L[0]), int(L[1]), L[2:])

            elif (int(L[0]) == 5 or int(L[0]) == 6):
                c.write(int(L[0]), int(L[1]), L[2])

            else:
                c.help()

if __name__ == "__main__":

    main()
