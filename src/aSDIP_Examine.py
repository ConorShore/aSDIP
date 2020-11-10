from cmd import Cmd
import pyshark

inpacket=pyshark.packet.packet.Packet()

class Examine_ui(Cmd):
    prompt = '(examine) >>> '
    intro = "Examine mode\nUsed to inspect packets to help in writing user functions"
    
    def do_from_file(self,s):
        s="/mnt/hgfs/OneDrive/Documents/University/Year 3/Project/GOOSE Spoofing/61850 Packet Capture/a_training_set1.pcapng"
        s=s.replace('\"','')

        try:
            packets=pyshark.FileCapture(s,display_filter="goose",include_raw=True,use_json=True)
        except:
            print("Could not find file")
            return False

        counter=0
        try:
            for element in packets:
                print(str(counter) + "\t" + element.eth.dst_raw[0] + "\t" + element.eth.src_raw[0])
                #print(element)
                counter+=1
        except:
            print()
        
        #create another UI to select target packet



        return False
        

    def help_from_file(self):
        print("Picks out packets from a specified file")
        print("Enclose filepath in \" \" marks")
        return 

    def do_livecapture(self,s):
        print("Waiting for packets")
        return

    def help_livecapture(self):
        print("Capture packets live to examine")
        print("pass a interface to listen to as arguement, without quotes")
        print("for example >>> livecapture ens33")
    