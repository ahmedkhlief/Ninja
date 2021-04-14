# Embedded file name: core\header.py
from core import config


def Banner():
    print ("""
            88             88
            ""             ""
                                              8888      8888
8b,dPPYba,  88 8b,dPPYba,  88 ,adPPYYba,    88        88    88
88P'   `"8a 88 88P'   `"8a 88 ""     `Y8    88              88
88       88 88 88       88 88 ,adPPPPP88    88              88
88       88 88 88       88 88 88,    ,88    88            88
88       88 88 88       88 88 `"8bbdP"Y8    88          88
                          ,88                 8888      888888
                        888P" 		      """)
    print ("                                  Version %s" % config.VERSION)
    print ("\nNinja C2 | Stealthy Pwn like a Ninja\n\n")
