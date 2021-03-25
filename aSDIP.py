#! /usr/bin/env python

#Known Bugs:
# 1. for some reason, when running this via rc.local, setting the interface by argument has no effect

import argparse
import sys
import os


#this is the file you execute

from src.aSDIP_UI import *
import RPi.GPIO as GPIO

GPIO.setmode(GPIO.BOARD)

def shutdown(channel):
    print('shutdown requested')
    os.system("sudo sh -c \"echo 1 >/sys/class/leds/led0/brightness\"")
    os.system("sudo sh -c \"echo 0 >/sys/class/leds/led1/brightness\"")
    os.system("sudo shutdown now")


parser = argparse.ArgumentParser()
parser.add_argument("-i","--interactive", help="Use in interactive mode",action="store_true")
parser.add_argument("-s","--sniff",type=str,help="sets sniff interface for non interactive mode")
parser.add_argument("-o","--output",type=str,help="sets output interface for non interactive mode")
parser.add_argument("-b","--button", help="Use this to execute from button press on GPIO2",action="store_true")
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
    if(args.button):
        os.system("sudo sh -c \"echo none >/sys/class/leds/led0/trigger\"")
        os.system("sudo sh -c \"echo none >/sys/class/leds/led1/trigger\"")        
        os.system("sudo sh -c \"echo 0 >/sys/class/leds/led1/brightness\"")
        os.system("sudo sh -c \"echo 1 >/sys/class/leds/led0/brightness\"")
        print("Waiting for button")
        GPIO.setup(11, GPIO.IN,pull_up_down=GPIO.PUD_UP)
        
        while(GPIO.input(11)==1):
            sleep(0.1)
        print("Button press recieved")
        os.system("sudo sh -c \"echo 1 >/sys/class/leds/led0/brightness\"")
        os.system("sudo sh -c \"echo 1 >/sys/class/leds/led1/brightness\"")
        sleep(2)
        GPIO.add_event_detect(11, GPIO.RISING, callback=shutdown)




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

