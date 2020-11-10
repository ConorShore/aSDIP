from cmd import Cmd
import pyshark

inpacket=pyshark.packet.packet.Packet()

class Examine_ui(Cmd):
    prompt = '(examine) >>> '
    intro = "Examine mode\nUsed to inspect packets to help in writing user functions"
    
    def do_from_file(self,s):
 
        pyshark.FileCapture(s,display_filter="ether proto 0x88b8")
        return True

    def help_from_file(self):
        print("Picks out packets from a specified file")
        print("Enclose filepath in \" \" marks")
        return True

    def do_livecapture(self,s):
        print("Waiting for packets")
        return

    def help_livecapture(self):
        print("Capture packets live to examine")
        print("pass a interface to listen to as arguement, without quotes")
        print("for example >>> livecapture ens33")
    