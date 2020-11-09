#! /usr/bin/env python

#scapy
from scapy.all import *
import goose
import pyshark

import sys
from enum import Enum

if 'little' == sys.byteorder:
    print("little")
else:
    print("big")

def BytesToStringRaw(invar):
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



def PrepareUnit(data,head):
    #pass head as string, with no 0x i.e "8f"
    #data can be of any type
    outpacket=bytes()
    outpacket=outpacket+BytesToStringRaw(head)
    outpacket=outpacket+BytesToStringRaw(int(len(data)/2))
    outpacket=outpacket+BytesToStringRaw(data)
    return outpacket

def StringToStringHex(input):
    s= ([ord(c) for c in input])
    string=""
    for element in s:
        string+=format(element,'x')
    return string


#sort out endianness (needs to be big)

# todo - add try except for capturing ctrl-c
# add vlan support

print("waiting for packet")
inpacket=pyshark.LiveCapture(interface="lo",bpf_filter="ether proto 0x88b8")
inpacket.sniff(packet_count=1)

# sniff will try to get packets from network, count=1 means get 1 packet then finish
#iface is the interface targetted, filter is a BPF (Berkely Packet Filter 
# https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
# which is used to only capture ethertype of 0x088b8, so GOOSE
# promisc="true" mean that it will listen for traffic not destined for itself, so everything

#edit packet here, edit inpacket directly




#setup the Ethernet part of the frame
outpacket=Ether(src=inpacket[0]['ETH'].src,dst=inpacket[0]['ETH'].dst,type=0x88b8)


#APPID conversion
b=bytes.fromhex(inpacket[0]['GOOSE'].APPID.raw_value)
outpacket=outpacket/b

#Length conversion
#b=bytes.fromhex(inpacket[0]['GOOSE'].Length.raw_value)
b=bytes.fromhex("00c5")
outpacket=outpacket/b

#reserve 1 and 2
b=bytes.fromhex("0000")
outpacket=outpacket/b
outpacket=outpacket/b

#61850 Begin Def
b=bytes.fromhex("61") #start condition
outpacket=outpacket/b
#PDUlength=127 #pdulength #121 #127
#outpacket=outpacket/BytesToStringRaw(PDUlength)

b=bytes.fromhex("81") 
outpacket=outpacket/b
b=bytes.fromhex("ba") 
outpacket=outpacket/b

#outpacket=outpacket/BytesToStringRaw(0)


#gocbRef
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].gocbRef.raw_value,0x80)

#TimeAllowtolive
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].timeAllowedtoLive.raw_value,0x81)

#you get the idea......
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].datSet.raw_value,0x82)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].goID.raw_value,0x83)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].t.raw_value,0x84)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].stNum.raw_value,0x85)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].sqNum.raw_value,0x86)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].test.raw_value,135) #test to see if no hex work
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].confRev.raw_value,0x88)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].ndsCom.raw_value,0x89)
outpacket=outpacket/PrepareUnit(inpacket[0]['GOOSE'].numDatSetEntries.raw_value,0x8A) ##change to you number of data members

#now for the payload
b=bytes.fromhex("AB") #start payload
outpacket=outpacket/b

#todo - auto calc of payload size
outpacket=outpacket/BytesToStringRaw(63) #how large is payload

for a in range(0,int(inpacket[0]['GOOSE'].get_field_value('alldata'))-1) :

    length = int(len(inpacket[0]['GOOSE'].get_field_value('bit_string').all_fields[a].raw_value)/2)+1
    datatype=inpacket[0]['GOOSE'].get_field_value('data').all_fields[a].show
    data=inpacket[0]['GOOSE'].get_field_value('ber_bitstring_padding').all_fields[a].show
    data+=inpacket[0]['GOOSE'].get_field_value('bit_string').all_fields[a].raw_value

    b=bytes.fromhex("84") #fix this awful hack
    outpacket=outpacket/b
    outpacket=outpacket/BytesToStringRaw(length) #how large is payload
    outpacket=outpacket/BytesToStringRaw("0"+data)

length = int(len(inpacket[0]['GOOSE'].get_field_value('bit_string').all_fields[13].raw_value)/2)+1
datatype=inpacket[0]['GOOSE'].get_field_value('data').all_fields[13].show
data=inpacket[0]['GOOSE'].get_field_value('ber_bitstring_padding').all_fields[13].show
data+=inpacket[0]['GOOSE'].get_field_value('bit_string').all_fields[13].raw_value

b=bytes.fromhex("84") #fix this awful hack
outpacket=outpacket/b
outpacket=outpacket/BytesToStringRaw(length) #how large is payload
outpacket=outpacket/BytesToStringRaw("0"+"31238")


##outpacket=outpacket/PrepareUnit(StringToStringHex("hello"),0x84)



#outpacket=outpacket/PrepareUnit("hello",0x84)





#outpacket=outpacket/inpacket[0]['GOOSE'].Length.raw_value
#todo, decode things other than bit-string
#print(inpacket[0]['GOOSE'].field_names)
#print()
#print()

#print(inpacket[0]['GOOSE'].get_field_value('APPID'))
#print(inpacket[0]['GOOSE'].get_field_value('ber_bitstring_padding').all_fields[12])

#print(inpacket[0]['GOOSE'].get_field_value('APPID').raw_value)


#for a in range(0,int(inpacket[0]['GOOSE'].get_field_value('alldata'))-1) :
   # print(i)
    #print(inpacket[0]['GOOSE'].get_field_value('data').all_fields[a].show)
  # print(inpacket[0]['GOOSE'].get_field_value('ber_bitstring_padding').all_fields[a].show)
   # print(inpacket[0]['GOOSE'].get_field_value('bit_string').all_fields[a].raw_value)

    #outpacket=outpacket/inpacket[0]['GOOSE'].Data[1]

sendp(outpacket,iface="lo")

#sendp(Ether(src=inpacket[0]['ETH'].src,dst=inpacket[0]['ETH'].dst,type=0x88b8),type=0x88b8,iface="lo")

#Ether() part gets source and dest macs and ether type and set to be correct



    
