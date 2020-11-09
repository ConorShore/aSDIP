#! /usr/bin/env python

#scapy
import pyshark
from socket import socket, AF_PACKET, SOCK_RAW

import sys


if 'little' == sys.byteorder:
    print("little")
else:
    print("big")

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

#edit packet here, edit inpacket directly


# to change a piece of data, call the LFC function with a string represneting the
# byte you want to cahnge
# an example:

#   #varibale change assigned object with string "8000" passed through 
#   #i.e change it to an IP type packet
#   inpacket.eth.type_raw[0]=pyshark.packet.fields.LayerFieldsContainer("8000")


#print(cap['GOOSE'].pretty_print())
#inpacket['GOOSE'].goosePdu_element.numDatSetEntries=221
#change=pyshark.packet.fields.LayerFieldsContainer('0f')

print(inpacket)

#ether header
outpacket=bytearray.fromhex(inpacket.eth.dst_raw[0])
outpacket+=bytearray.fromhex(inpacket.eth.src_raw[0])
outpacket+=bytearray.fromhex(inpacket.eth.type_raw[0])

#GOOSE header
outpacket+=bytearray.fromhex(inpacket.goose.appid_raw[0])
outpacket+=bytearray.fromhex(inpacket.goose.length_raw[0])
outpacket+=bytearray.fromhex(inpacket.goose.reserve1_raw[0])
outpacket+=bytearray.fromhex(inpacket.goose.reserve2_raw[0])

# Start byte
outpacket+=bytearray.fromhex("61")

#Actually no idea what this is for, but ABB have it in there
outpacket+=bytearray.fromhex("81")

#thanks python for being bad
print(int(int(len(inpacket.goose.goosePdu_element_raw[0]))/2))
##might be stored in goosePdu_element_raw[2] testing required

#calculates the 0x61 length
outpacket+=DataToBytesRaw(int(int(len(inpacket.goose.goosePdu_element_raw[0]))/2))

#gocb
outpacket+=bytearray.fromhex("80")
#outpacket+=bytearray.fromhex("1c")
outpacket+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.gocbRef_raw[2]))
outpacket+=bytearray.fromhex(inpacket.goose.goosePdu_element.gocbRef_raw[0])






print(outpacket)

sock=socket(AF_PACKET,SOCK_RAW)
sock.bind(('lo', 0))
#print(inpacket.get_raw_packet())
#print(bytearray(inpacket.get_raw_packet()))
sock.send(bytearray(outpacket))




