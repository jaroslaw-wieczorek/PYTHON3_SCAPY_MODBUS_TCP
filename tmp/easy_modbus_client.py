##
from EasyModbus import ModbusClient
from EasyModbus import modbusexceptions
modbusClient = ModbusClient.ModbusClient("127.0.0.1", 502)
modbusClient.Connect()
#readCoils = modbusClient.ReadCoils(43, 5)
#print(readCoils)
#readDiscreteInputs = modbusClient.ReadDiscreteInputs(65535, 10)
#print(readDiscreteInputs)
#readHoldingRegisters = modbusClient.ReadHoldingRegisters(65535, 2)
#print(readHoldingRegisters)
#writeSingleCoil = modbusClient.WriteSingleCoil(1, 5)
#print(writeSingleCoil)
#writeSingleRegister = modbusClient.WriteSingleRegister(65535, 65535)
#print(writeSingleRegister)

writeMultipleRegisters = modbusClient.WriteMultipleRegisters(65535, 535)
print(writeMultipleRegisters)
writeMultipleCoils = modbusClient.WriteMultipleCoils(65535, 535)
print(writeMultipleCoils)

modbusClient.close()
