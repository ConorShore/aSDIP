
#this is where packets are recieved and encoded


#BUGS:
#large packet sizes cause excpetion, because dataToBytesRaw can't handle it

import pyshark
from socket import socket, AF_PACKET, SOCK_RAW

import sys
import netifaces

from .aSDIP_Arb_Code import yourcode
from .aSDIP_Header import LFC

from math import floor

from multiprocessing import Pool
from multiprocessing import Process,Value,Manager
from multiprocessing.managers import BaseManager,MakeProxyType,public_methods

from time import sleep,time


ininterface="lo"

outinterface="lo"

def is_interface_up(interface):
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr

def changeinif(invar):
    globals()['ininterface']=invar
    return

def changeoutif(invar):
    globals()['outinterface']=invar
    return

def DataToBytesRaw(invar):
    temp=0
    templit0=0
    templit1=0
    i=0
    count=0


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

class packetsend(object):
 
    def __init__(self):
        self.__plist=[]

    def clear(self):
        self.__plist.clear()

    def add(self,packet):
        if(isinstance(packet,list)):
            self.__plist.extend(packet)
        else:
            self.__plist.append(packet)

    def send(self,interface):
        #Send the packet
        if(len(self.__plist)>0):
            sock=socket(AF_PACKET,SOCK_RAW)
            sock.bind((interface, 0))
            for packet in self.__plist:
                sock.send(packet,0)
            self.clear()
            return True
        else:
            return False

    def __len__(self):
        return len(self.__plist)

    def print(self):
        print(self.__plist)

import signal, time

class Timeout():
  """Timeout class using ALARM signal"""
  class Timeout(Exception): pass

  def __init__(self, sec):
    self.sec = sec

  def __enter__(self):
    signal.signal(signal.SIGALRM, self.raise_timeout)
    signal.alarm(self.sec)

  def __exit__(self, *args):
    signal.alarm(0) # disable alarm

  def raise_timeout(self, *args):
    raise Timeout.Timeout()

def printer():
    print("this pro")
    return




class packetbuff(object):
 
    def __init__(self):
        self.__plist=[]

    def clear(self):
        self.__plist.clear()
        self.__plist=[]

    def add(self,packet):
        self.__plist.append(packet)

    def get(self):
        print("a" + str(type(self.__plist)))
        l=self.__plist
        #self.clear()
        return l
        
    def __len__(self):
        return len(self.__plist)

    def print(self):
        print("no of packets = " + str(self.__plist))
        print(self.__plist)


# todo:
# add vlan support



def intercept():
    print("waiting for packet")
    #look at packets_from_tshark async
    # sendpro = Process(target=processpacket)
    senderproxy = MakeProxyType('sender',('add','send','print','__len__'))
    buffproxy = MakeProxyType('buff',('add','push','clear','print','__len__','get'))
    BaseManager.register('sender',packetsend,senderproxy)
    BaseManager.register('buff',packetbuff,buffproxy)
    manager=BaseManager()
    manager.start()
    sendo=manager.sender()
    buffo=manager.buff()

    sync=Value('i',0)

    

    def getpacket():
        cap=pyshark.LiveCapture(interface=ininterface,bpf_filter="ether proto 0x88b8",include_raw=True,use_json=True)
        try:
            cap.apply_on_packets(buffo.add)
        except KeyboardInterrupt:
            print("bye")
            return
        return
            
    
    buffersize=1000
    timeoutms=10000
    millis = lambda: int(round(time.time() * 1000))
    
    #sleeptime=1

    def movesendpackets():
        print("hello")
        lasttime=millis()
        s=Process(target=getpacket)
        s.start()
        while(1):
            try:
                if(len(buffo)>=buffersize):
                    print("Size push " + str(len(buffo)))
                    lis=buffo.get()
                    buffo.clear()
                    processpacket(lis,sendo)
                    s.terminate()
                    sendo.send(outinterface)
                    s.join()
                    s=Process(target=getpacket)
                    s.start()
                elif(((millis())>(lasttime+timeoutms))and(len(buffo)>0)):
                    a=millis()
                    print("Timeout push " + str(len(buffo)))
                    lasttime=millis()
                    lis=buffo.get()
                    buffo.clear()
                    processpacket(lis,sendo)
                    b=millis()
                    s.terminate()
                    sendo.send(outinterface)
                    s=Process(target=getpacket)
                    s.start()   
                    print(millis()-b)
                    print(millis()-a)                
            except KeyboardInterrupt:
                print("p bye")
                s.terminate()

                s.join()
                try:
                    if(len(buffo)>0):
                        print("clearing buffer of packets: " + str(len(buffo)))
                        print("b" + str(type(buffo.get())))
                        processpacket(buffo.get(),sendo)
                        buffo.clear() 
                        sendo.send(outinterface)
                except:
                    print("Final clear error")
                return
            except BrokenPipeError:
                print("pipe went bye")
            except:
                print("Error occured")
                return
        

    movesendpackets()

    print()
    print("Leaving intercept mode")
    return




def processpacket(capture,sender):
    for inpacket in capture:
        


    # outinterface="ens33"
        # sniff will try to get packets from network, count=1 means get 1 packet then finish
        #iface is the interface targetted, filter is a BPF (Berkely Packet Filter 
        # https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)
        # which is used to only capture ethertype of 0x088b8, so GOOSE
        

        #this function executes your code on the recieved packet
        yourcode(inpacket)

        #Rebuild the packet

        #rebuild data
        counter=0
        databytes=bytearray()
        for element in inpacket.goose.goosePdu_element.allData_tree.Data:
            #the BER code i.e 0x84 etc
            databytes+=DataToBytesRaw(int(element)+128)
            #the length of data
            databytes+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][2]))
            #the data (may include padding value)
            databytes+=bytearray.fromhex(inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0])
            counter+=1

        inpacket.goose.goosePdu_element.allData_raw[0].raw_value=databytes


        #put correct value for number of entries in
        inpacket.goose.goosePdu_element.numDatSetEntries_raw[2].raw_value=str(counter)

        #gocb
        gooseAPDU=bytearray.fromhex("80")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.gocbRef_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.gocbRef_raw[0])

        #ttl
        gooseAPDU+=bytearray.fromhex("81")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.timeAllowedtoLive_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.timeAllowedtoLive_raw[0])

        #datSet
        gooseAPDU+=bytearray.fromhex("82")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.datSet_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.datSet_raw[0])

        #goID
        gooseAPDU+=bytearray.fromhex("83")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.goID_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.goID_raw[0])

        #time
        gooseAPDU+=bytearray.fromhex("84")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.t_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.t_raw[0])

        #stNum
        gooseAPDU+=bytearray.fromhex("85")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.stNum_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.stNum_raw[0])

        #sqNum
        gooseAPDU+=bytearray.fromhex("86")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.sqNum_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.sqNum_raw[0])

        #test
        gooseAPDU+=bytearray.fromhex("87")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.test_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.test_raw[0])

        #confRev
        gooseAPDU+=bytearray.fromhex("88")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.confRev_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.confRev_raw[0])

        #ndsCom
        gooseAPDU+=bytearray.fromhex("89")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.ndsCom_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.ndsCom_raw[0])

        #numDatSetEntries
        gooseAPDU+=bytearray.fromhex("8A")
        gooseAPDU+=DataToBytesRaw(int(inpacket.goose.goosePdu_element.numDatSetEntries_raw[2]))
        gooseAPDU+=bytearray.fromhex(inpacket.goose.goosePdu_element.numDatSetEntries_raw[0])


        #build goosePdu_element
        goosefull=gooseAPDU
        datalen=int(int(len(inpacket.goose.goosePdu_element.allData_raw[0]))/2)
        goosefull+=bytearray.fromhex("AB")
        if(datalen>=256):
            goosefull+=bytearray.fromhex("82")
            goosefull+=DataToBytesRaw(int(floor(datalen/256)))
            goosefull+=DataToBytesRaw(int(datalen%256))
        else:
            goosefull+=DataToBytesRaw(datalen)


        goosefull+=databytes
        
        # Start byte of goose pdu
        #todo clean up these variable names

        goosefull2=bytearray.fromhex("61")

        

        len_61=int(int(len(inpacket.goose.goosePdu_element_raw[0]))/2)
        if(len_61>=256):
            goosefull2+=bytearray.fromhex("82")
            goosefull2+=DataToBytesRaw(int(floor(len_61/256)))
            goosefull2+=DataToBytesRaw(int(len_61%256))
        else:
            goosefull2+=bytearray.fromhex("81")
            #calculates the 0x61 length
            goosefull2+=DataToBytesRaw(int(int(len(inpacket.goose.goosePdu_element_raw[0]))/2))
        
        
        goosefull2+=goosefull

        inpacket.goose.goosePdu_element_raw[0].raw_value=goosefull

        
        #GOOSE header
        goosehead=bytearray.fromhex(inpacket.goose.appid_raw[0])
        #Actually read length of packet
        

        gooselen=(int(len(goosefull2)+8))

        goosehead+=DataToBytesRaw(int(floor(gooselen/256)))
        goosehead+=DataToBytesRaw(int(gooselen%256))
        
        goosehead+=bytearray.fromhex(inpacket.goose.reserve1_raw[0])
        goosehead+=bytearray.fromhex(inpacket.goose.reserve2_raw[0])

        #ether header
        etherhead=bytearray.fromhex(inpacket.eth.dst_raw[0])
        etherhead+=bytearray.fromhex(inpacket.eth.src_raw[0])
        etherhead+=bytearray.fromhex(inpacket.eth.type_raw[0])

        #start packet off with ethernet header and carry on stacking
        outpacket=etherhead

        outpacket+=goosehead




        outpacket+=goosefull2

        #bind a raw socket to transmit packet on



        #check to see it there's trailing bytes, if so grab them from the raw packet and add on

        trailingbyte=len(bytearray.fromhex(inpacket.frame_raw.value))-len(outpacket)
        rawpacket=bytearray.fromhex(inpacket.frame_raw.value)

        if trailingbyte>0:
            
            outpacket+=rawpacket[len(outpacket):len(bytearray.fromhex(inpacket.frame_raw.value))]
        sender.add(outpacket)
        sys.stdout.flush()
