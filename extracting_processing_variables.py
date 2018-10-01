"""Scapy Client for ModbusTCP."""
# !/usr/bin/python3

from scapy.all import *
from scapy.contrib.modbus import *

counter = 0
list_modbus_data = []
filename = "wszystkie_zmienne_procesowe"

import csv


myfile = open(filename, 'w+')
wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)

""" 
Działanie skrypu wyciągającego zmienne procesowe dla prtokołu Modbus/TCP.

Skrypt przyjmuje plik pcap lub pcapng zawierający ruch sieciowy.

Za pomocą biblioteki Scapy odczytywany jest pakiet po pakiecie znajdujący się w podanym pliku. 

Podczas odczytywania pakitow wykonywna jest funckja sniff_callback. 

W biblitoece SCAPY została zaimplementowana obsługa następujących kodów funkcyjnych: 01, 02, 03, 04, 05, 06, 07, 15 i 16

Lista kodów i ich znacznie:    
    01  -   ModbusPDU01ReadCoils

    02  -   ModbusPDU02ReadDiscreteInputs

    03  -   ModbusPDU03ReadHoldingRegisters

    04  -   ModbusPDU04ReadInputRegisters

    05  -   ModbusPDU05WriteSingleCoil

    06  -   ModbusPDU06WriteSingleRegister

    07  -   ModbusPDU07ReadExceptionStatus

    08  -   ModbusPDU0FWriteMultipleCoils

    09  -   ModbusPDU10WriteMultipleRegisters

W pierwszej kolejności sprawdzane jest: Czy analizowany pakiet jest requestem, czy responsem protokołu Modbus/TCP - jeśli nie jest żadnym z nich zostaje pominięty.

Nastpęnie po ustaleniu typu pakietu i kodu funkcji, zostaje on zapisywany do pliku tekstowego jako lista z podziałem na wszystkie pola.

Aby kontrolować konkretną zmienną procesorową należy kontrolować odpowiedzi urządzenia, znać jej położenie oraz miejsce przechowywania (np numer rejestru), a następnie odfiltrować wybrane wartości.


"""
 
def sniff_callback(pkt):
    global counter, wr

    # sprawdzenie czy pakiet zawiera żądanie
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
            req[5] = [b.funcCode, b.startingAddr, b.quantityOutput,
                      b.byteCount, b.outputsValue]

        elif pkt.haslayer(ModbusPDU10WriteMultipleRegistersRequest):
            b = pkt["ModbusPDU10WriteMultipleRegistersRequest"]
            req[5] = [b.funcCode, b.startingAddr, b.quantityRegisters,
                      b.byteCount, b.outputsValue]

        wr.writerow(req)


    # sprawdzenie czy pakiet zawiera odpowiedź
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

        elif pkt.haslayer(ModbusPDU10WriteMultipleRegistersResponse):
            b = pkt["ModbusPDU10WriteMultipleRegistersResponse"]
            req[5] = [b.funcCode, b.startingAddr, b.quantityRegisters]

        wr.writerow(req)

    counter += 1
    if counter % 10000 == 0:
        print(counter)


def sniff_packets(filename):
    print("Sniff")
    global list_modbus_data

    packets = sniff(offline=filename, prn=sniff_callback)
    print("Packets:", len(packets))


def main():
    global wr, myfile
    filename = "bms.pcap"
    sniff_packets(filename)
    myfile.close()


if __name__ == '__main__':
    main()
