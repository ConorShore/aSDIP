#! /usr/bin/env python


#this is the file you execute

from src.aSDIP_UI import *

try:
    main_ui().cmdloop()
except KeyboardInterrupt:
    print()
    print("Bye!")
except EOFError:
    print()
    print("bye!")