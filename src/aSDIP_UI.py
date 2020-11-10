#this is where the UI is run from

import os.path

import readline

histfile = os.path.expanduser('~/.someconsole_history')
histfile_size = 1000

from cmd import Cmd
from .aSDIP_Engine import *
from .aSDIP_Examine import *


class Select_ui(Cmd):
    prompt = '(sel)\t>>> '
    intro = "Select mode\nUsed to select the packet you want to examine"
    
    def do_select(self,s):
        return select_from_file(s)

    def help_select(self):
        print("Select which packet you want to analyse")
        print("Example: >>> select 35")

class Examine_ui(Cmd):
    prompt = '(ex)\t>>> '
    intro = "Examine mode\nUsed to inspect packets to help in writing user functions"
    
    def do_from_file(self,s):
        if(sniff_from_file(s)==True):
            Select_ui_obj.cmdloop()
        else:
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
    


Examine_ui_obj=Examine_ui()
Select_ui_obj=Select_ui()




class main_ui(Cmd):
    prompt = '(main)\t>>> '
    intro = "aSDIP - 61850 packet manipulator - Type ? to list commands\nBy default lo is used for in and out"

    def do_exit(self,s):
        print("Bye")
        return True

    def help_exit(self):
        print("Exits the program")
        return
 
    def do_intercept(self,s):
        print("Beginning Intercept")
        intercept()
        return

    def help_intercept(self):
        print("Will intercept packets and run functions defined")
        return

    def do_set_sniff_if(self,s):
        print("Setting sniff interface to " + s)
        try:
            if(is_interface_up(s)==True):
                changeinif(s)
        except ValueError:
            print("Network adapter doesn't exist: " + s)
        return
    
    def help_set_sniff_if(self,s):
        print("Used to set sniff interface. dont use quotes or spaces, just write the if name")
        print("An example >>> set_sniff_if ens33")
        return

    def do_set_out_if(self,s):
        print("Setting output interface to " + s)
        try:
            if(is_interface_up(s)==True):
                changeoutif(s)
        except ValueError:
            print("Network adapter doesn't exist: " + s)
        return
        
    def help_set_out_if(self,s):
        print("Used to set sniff interface. dont use quotes or spaces, just write the if name")
        print("An example >>> set_out_if ens33")
        return

    def do_examine(self,s):
        try:
            Examine_ui_obj.cmdloop()
        except KeyboardInterrupt:
            print()
            return True

