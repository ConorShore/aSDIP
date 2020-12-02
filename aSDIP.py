#! /usr/bin/env python

import argparse
import sys


#this is the file you execute

from src.aSDIP_UI import *


parser = argparse.ArgumentParser()
parser.add_argument("-i","--interactive", help="Use in interactive mode",action="store_true")
parser.add_argument("-s","--sniff",type=str,help="sets sniff interface for non interactive mode")
parser.add_argument("-o","--output",type=str,help="sets output interface for non interactive mode")
args = parser.parse_args()

if(args.interactive):
    try:
        main_ui().cmdloop()
    except KeyboardInterrupt:
        print()
        print("Bye!")
    except EOFError:
        print()
        print("bye!")
else:
    log = open("aSDIP.log", "a")
    sys.stdout = log
    if(args.sniff is not None):
        main_ui().do_set_sniff_if(args.sniff)
    if(args.output is not None):
        main_ui().do_set_out_if(args.output)
    try:
        main_ui().do_intercept(1)
    except KeyboardInterrupt:
        print()
        print("Bye!")
    except EOFError:
        print()
        print("bye!")