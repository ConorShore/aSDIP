from cmd import Cmd
import pyshark

inpacket=pyshark.packet.packet.Packet()
packets=0

def sniff_from_file(s):
    s="/mnt/hgfs/OneDrive/Documents/University/Year 3/Project/GOOSE Spoofing/61850 Packet Capture/Single GOOSE.pcapng"
    s=s.replace('\"','') #get rid of quote marks if they are present

    try:
        globals()['packets']=pyshark.FileCapture(s,display_filter="goose",include_raw=True,use_json=True)
    except:
        print("Could not find file")
        return False

    counter=0
    print("Number\tDst\t\tSrc\t\tEtherType")
    try:
        for element in packets:
            print(str(counter) + "\t" + element.eth.dst_raw[0] + "\t" + element.eth.src_raw[0] + "\t0x" + element.eth.type_raw[0])
            #print(element)
            counter+=1
    except:
        print()
        return False
  
    return True
    #create another UI to select target packet

def select_from_file(s):
    if (s.isnumeric()==True):
        try:
            print("Selecting packet " + s)
            print("This can take a moment.....")
            globals()['inpacket']=globals()['packets'][int(s)]
            return True
        except IndexError:
            print("number out of range")
            return False
        except:
            print("Unhandeled error")
            return False
    else:
        print("Please enter a proper number")
        return False

    return False
