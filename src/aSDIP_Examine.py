from cmd import Cmd
import pyshark

inpacket=pyshark.packet.packet.Packet()
packets=0

class Examine_ui(Cmd):
    prompt = '(ex)\t>>> '
    intro = "Examine mode\nUsed to inspect packets to help in writing user functions"
    
    def do_from_file(self,s):
        s="/mnt/hgfs/OneDrive/Documents/University/Year 3/Project/GOOSE Spoofing/61850 Packet Capture/Single GOOSE.pcapng"
        s=s.replace('\"','')

        try:
        
           globals()['packets']=pyshark.FileCapture(s,display_filter="goose",include_raw=True,use_json=True)
        except:
            print("Could not find file")
            return False

        counter=0
        print("Number\tDst\t\t\tSrc\t\t\tEtherType")
        try:
            for element in packets:
                print(str(counter) + "\t" + element.eth.dst_raw[0] + "\t" + element.eth.src_raw[0] + "\t" + element.eth.type_raw[0])
                #print(element)
                counter+=1
        except:
            print()
        Select_ui().cmdloop()
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
    
class Select_ui(Cmd):
    prompt = '(sel)\t>>> '
    intro = "Select mode\nUsed to select the packet you want to examine"
    
    def do_select(self,s):
        print(s.isnumeric())
        if (s.isnumeric()==True):
            try:
                print("Selecting packet " + s)
                print("This can take a moment.....")
                globals()['inpacket']=globals()['packets'][int(s)]
                return True
            except IndexError:
                print("number out of range")
                return
            except:
                print("Unhandeled error")
                return

            print("Examining packet " + int(s))
        else:
            print("Please enter a proper number")
            return

    def help_select(self):
        print("Select which packet you want to analyse")
        print("Example: >>> select 35")


