#! /usr/bin/env python

#scapy
import pyshark
from socket import socket, AF_PACKET, SOCK_RAW

import sys


ininterface="lo"
outinterface="lo"

def DataToBytesRaw(invar):
    temp=0
    templit0=0
    templit1=0
    i=0
    count=0
    base=0


    if (isinstance(invar,str)) or (isinstance(invar,bytes)):
        temp=bytearray(int(len(invar)/2))
        for element in invar:
            if(count==0):
                templit0=int(element,16)*16
            else:
                templit1=int(element,16)
            count+=1
            if(count==2):
                count=0
                temp[i]=templit0+templit1
                i+=1
    else:
        temp = bytearray(1)
        temp[0]=invar
        #todo - need to do something more robust here for larger numbers
    
    return bytes(temp)



def StringToStringHex(input):
    s= ([ord(c) for c in input])
    string=""
    for element in s:
        string+=format(element,'x')
    return string

def LFC(str):
    # literally here to save my hands this function is
    #used to create the object used to change variable names
    return pyshark.packet.fields.LayerFieldsContainer(str)

# taken from mdehus's goose-IEC61850-scapy repo
# GPL-2.0
# https://github.com/mdehus/goose-IEC61850-scapy




#sort out endianness (needs to be big)

# todo - add try except for capturing ctrl-c
# add vlan support

print("waiting for packet")
cap=pyshark.LiveCapture(interface="lo",bpf_filter="ether proto 0x88b8",include_raw=True,use_json=True)
cap.sniff(packet_count=1)

inpacket=cap[0]
# sniff will try to get packets from network, count=1 means get 1 packet then finish
#iface is the interface targetted, filter is a BPF (Berkely Packet Filter 
# https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
# which is used to only capture ethertype of 0x088b8, so GOOSE
# promisc="true" mean that it will listen for traffic not destined for itself, so everything

##edit packet between here



##and here


# to change a piece of data, you need to edit the raw.data field of that data
# i'm pretty sure every raw data is formatted as a string
# an example:

#   #varibale change assigned object with string "8000" passed through 
#   #i.e change it to an IP type packet
#   inpacket.eth.type_raw[0].raw_data="8000"

#changing data in packet
#
#inpacket.goose.goosePdu_element.allData_tree.Data_raw[0][0]

#packet rebuild

#rebuild data
counter=0
databytes=bytearray()
for element in inpacket.goose.goosePdu_element.allData_tree.Data:
    databytes+=DataToBytesRaw(int(element)+128)
    databytes+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][2]))
    databytes+=bytearray.fromhex(inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0])
    counter+=1

inpacket.goose.goosePdu_element.allData_raw[0].raw_value=databytes


#set put correct value for number of entries in
inpacket.goose.goosePdu_element.numDatSetEntries_raw[2].raw_value=str(counter)

inpacket.goose.goosePdu_element_raw[0]

#todo, get the extra stuff after pdu

#ether header
etherhead=bytearray.fromhex(inpacket.eth.dst_raw[0])
etherhead+=bytearray.fromhex(inpacket.eth.src_raw[0])
etherhead+=bytearray.fromhex(inpacket.eth.type_raw[0])

#GOOSE header
goosehead=bytearray.fromhex(inpacket.goose.appid_raw[0])
goosehead+=bytearray.fromhex(inpacket.goose.length_raw[0])
goosehead+=bytearray.fromhex(inpacket.goose.reserve1_raw[0])
goosehead+=bytearray.fromhex(inpacket.goose.reserve2_raw[0])





#gocb
goosenondata=bytearray.fromhex("80")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.gocbRef_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.gocbRef_raw[0])

#ttl
goosenondata+=bytearray.fromhex("81")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.timeAllowedtoLive_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.timeAllowedtoLive_raw[0])

#datSet
goosenondata+=bytearray.fromhex("82")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.datSet_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.datSet_raw[0])

#goID
goosenondata+=bytearray.fromhex("83")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.goID_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.goID_raw[0])

#time
goosenondata+=bytearray.fromhex("84")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.t_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.t_raw[0])

#stNum
goosenondata+=bytearray.fromhex("85")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.stNum_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.stNum_raw[0])

#sqNum
goosenondata+=bytearray.fromhex("86")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.sqNum_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.sqNum_raw[0])

#test
goosenondata+=bytearray.fromhex("87")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.test_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.test_raw[0])

#confRev
goosenondata+=bytearray.fromhex("88")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.confRev_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.confRev_raw[0])

#ndsCom
goosenondata+=bytearray.fromhex("89")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.ndsCom_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.ndsCom_raw[0])

#numDatSetEntries
goosenondata+=bytearray.fromhex("8A")
goosenondata+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.numDatSetEntries_raw[2]))
goosenondata+=bytearray.fromhex(inpacket.goose.goosePdu_element.numDatSetEntries_raw[0])


#build goosePdu_element
goosefull=goosenondata
goosefull+=bytearray.fromhex("AB")
goosefull+=DataToBytesRaw(int(int(len(inpacket.goose.goosePdu_element.allData_raw[0]))/2))
goosefull+=databytes
inpacket.goose.goosePdu_element_raw[0].raw_value=goosefull

#start packet of with ethernet header
outpacket=etherhead

outpacket+=goosehead

# Start byte
outpacket+=bytearray.fromhex("61")

#Actually no idea what this is for, but ABB have it in there
outpacket+=bytearray.fromhex("81")


#calculates the 0x61 length
outpacket+=DataToBytesRaw(int(int(len(inpacket.goose.goosePdu_element_raw[0]))/2))

outpacket+=goosefull


sock=socket(AF_PACKET,SOCK_RAW)
sock.bind(('lo', 0))


#check to see it there's trailing bytes, if so grab them from the raw packet and add on

trailingbyte=len(bytearray.fromhex(inpacket.frame_raw.value))-len(outpacket)
rawpacket=bytearray.fromhex(inpacket.frame_raw.value)

if trailingbyte>0:
    print(rawpacket[len(outpacket):len(bytearray.fromhex(inpacket.frame_raw.value))])
    
    outpacket+=rawpacket[len(outpacket):len(bytearray.fromhex(inpacket.frame_raw.value))]

sock.send(outpacket)




