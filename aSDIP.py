#! /usr/bin/env python

import argparse


#this is the file you execute

from src.aSDIP_UI import *

parser = argparse.ArgumentParser()
parser.parse_args()
parser.add_argument("--interactive",help="Interactive Mode")
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