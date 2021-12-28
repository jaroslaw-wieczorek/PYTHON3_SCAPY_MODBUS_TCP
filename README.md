# PYTHON3_SCAPY_MODBUS_TCP

### This repository contains modified libaries from smod repository - MODBUS Penetration Testing Framework(python 2.x). My repository contains a modification that allows create Modbus stack and work in the Scapy library for Python 3.x. 


INSTALATION:
1. Create virtualenv:
+ $ virtualenv env
  
2. Install dependecies pip3: 
+ $ pip3 install scapy
  
3. Add my libaries:
+ $ cp -r Mobus ./env/lib/python3.x/site-package/
  

```Python
# Example of use:
>>> from Modbus.Modbus import *
>>> pkt = ip/tcp/ModbusADU()
>>> pkt.show()
###[ IP ]### 
  version= 4
  ihl= None
  tos= 0x0
  len= None
  id= 1
  flags= 
  frag= 0
  ttl= 64
  proto= tcp
  chksum= None
  src= 192.168.179.129
  dst= 192.168.179.131
  \options\
###[ TCP ]### 
     sport= 12345
     dport= 502
     seq= 0
     ack= 0
     dataofs= None
     reserved= 0
     flags= S
     window= 8192
     chksum= None
     urgptr= 0
     options= {}
###[ ModbusADU ]### 
        transId= 0x1
        protoId= 0x0
        len= None
        unitId= 0x0
>>>
>>> pkt = ip/tcp/ModbusADU()/ModbusPDU
## TAB-TAB
ModbusPDU01_Read_Coils               
ModbusPDU04_Read_Input_Registers_Exception      
ModbusPDU0F_Write_Multiple_Coils_Answer
ModbusPDU01_Read_Coils_Answer                   
ModbusPDU05_Write_Single_Coil                   
ModbusPDU0F_Write_Multiple_Coils_Exception
ModbusPDU01_Read_Coils_Exception                
ModbusPDU05_Write_Single_Coil_Answer            
ModbusPDU10_Write_Multiple_Registers
ModbusPDU02_Read_Discrete_Inputs                
ModbusPDU05_Write_Single_Coil_Exception         
ModbusPDU10_Write_Multiple_Registers_Answer
ModbusPDU02_Read_Discrete_Inputs_Answer        
ModbusPDU06_Write_Single_Register               
ModbusPDU10_Write_Multiple_Registers_Exception
ModbusPDU02_Read_Discrete_Inputs_Exception      
ModbusPDU06_Write_Single_Register_Answer        
ModbusPDU11_Report_Slave_Id
ModbusPDU03_Read_Holding_Registers              
ModbusPDU06_Write_Single_Register_Exception     
ModbusPDU11_Report_Slave_Id_Answer
ModbusPDU03_Read_Holding_Registers_Answer       
ModbusPDU07_Read_Exception_Status               
ModbusPDU11_Report_Slave_Id_Exception
ModbusPDU03_Read_Holding_Registers_Exception    
ModbusPDU07_Read_Exception_Status_Answer        
ModbusPDU_Read_Generic
ModbusPDU04_Read_Input_Registers                
ModbusPDU07_Read_Exception_Status_Exception     
>>> pkt = ip/tcp/ModbusADU()/ModbusPDU

```
  





